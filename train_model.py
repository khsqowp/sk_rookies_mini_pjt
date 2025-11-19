# train_multi_models.py
"""
다양한 모델(RF, CNN, BART)을 학습하고 성능 비교
"""
import json
from pathlib import Path
from typing import Dict, Tuple, Any
import warnings
warnings.filterwarnings('ignore')

import pandas as pd
import numpy as np
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import VarianceThreshold
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report, 
    roc_auc_score, 
    f1_score,
    precision_score,
    recall_score,
    accuracy_score,
    confusion_matrix
)

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader

from config import MODEL_PATH, BENIGN_STATS_PATH, FEATURES_PATH

CSV_PATH = Path(
    r"C:\Users\sec\OneDrive\바탕 화면\SK쉴더스\ransom_dectection_model\sk_rookies_mini_pjt\Ransomware_headers.csv"
)

TOP_K_FEATURES = 256


# ==================== 데이터셋 클래스 ====================
class HeaderDataset(Dataset):
    """PyTorch Dataset for PE Header data"""
    def __init__(self, X, y):
        self.X = torch.FloatTensor(X)
        self.y = torch.LongTensor(y)
    
    def __len__(self):
        return len(self.y)
    
    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]


# ==================== CNN 모델 ====================
class HeaderCNN(nn.Module):
    """1D CNN for PE Header analysis"""
    def __init__(self, input_size=256):
        super(HeaderCNN, self).__init__()
        
        # 1D Convolution layers
        self.conv1 = nn.Conv1d(1, 64, kernel_size=5, padding=2)
        self.bn1 = nn.BatchNorm1d(64)
        self.pool1 = nn.MaxPool1d(2)
        
        self.conv2 = nn.Conv1d(64, 128, kernel_size=5, padding=2)
        self.bn2 = nn.BatchNorm1d(128)
        self.pool2 = nn.MaxPool1d(2)
        
        self.conv3 = nn.Conv1d(128, 256, kernel_size=3, padding=1)
        self.bn3 = nn.BatchNorm1d(256)
        self.pool3 = nn.MaxPool1d(2)
        
        # Calculate flattened size
        conv_output_size = input_size // 8  # After 3 pooling layers
        
        # Fully connected layers
        self.fc1 = nn.Linear(256 * conv_output_size, 512)
        self.dropout1 = nn.Dropout(0.5)
        self.fc2 = nn.Linear(512, 128)
        self.dropout2 = nn.Dropout(0.3)
        self.fc3 = nn.Linear(128, 2)
        
        self.relu = nn.ReLU()
    
    def forward(self, x):
        # x shape: (batch, features) -> (batch, 1, features)
        x = x.unsqueeze(1)
        
        x = self.pool1(self.relu(self.bn1(self.conv1(x))))
        x = self.pool2(self.relu(self.bn2(self.conv2(x))))
        x = self.pool3(self.relu(self.bn3(self.conv3(x))))
        
        # Flatten
        x = x.view(x.size(0), -1)
        
        x = self.dropout1(self.relu(self.fc1(x)))
        x = self.dropout2(self.relu(self.fc2(x)))
        x = self.fc3(x)
        
        return x


# ==================== BART-style Transformer ====================
class HeaderTransformer(nn.Module):
    """Transformer Encoder for PE Header analysis"""
    def __init__(self, input_size=256, d_model=256, nhead=8, num_layers=4):
        super(HeaderTransformer, self).__init__()
        
        self.embedding = nn.Linear(1, d_model)
        self.pos_encoder = nn.Parameter(torch.randn(1, input_size, d_model))
        
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=1024,
            dropout=0.1,
            batch_first=True
        )
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        
        self.fc1 = nn.Linear(d_model * input_size, 512)
        self.dropout = nn.Dropout(0.3)
        self.fc2 = nn.Linear(512, 2)
        self.relu = nn.ReLU()
    
    def forward(self, x):
        # x shape: (batch, features) -> (batch, features, 1)
        x = x.unsqueeze(-1)
        
        # Embedding
        x = self.embedding(x)  # (batch, features, d_model)
        x = x + self.pos_encoder
        
        # Transformer encoding
        x = self.transformer_encoder(x)
        
        # Flatten and classify
        x = x.view(x.size(0), -1)
        x = self.dropout(self.relu(self.fc1(x)))
        x = self.fc2(x)
        
        return x


# ==================== 모델 학습 함수 ====================
def train_pytorch_model(
    model: nn.Module,
    train_loader: DataLoader,
    val_loader: DataLoader,
    epochs: int = 50,
    device: str = 'cuda' if torch.cuda.is_available() else 'cpu'
) -> Tuple[nn.Module, Dict[str, float]]:
    """PyTorch 모델 학습"""
    model = model.to(device)
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-5)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', patience=5, factor=0.5)
    
    best_val_loss = float('inf')
    best_model_state = None
    patience_counter = 0
    max_patience = 10
    
    for epoch in range(epochs):
        # Training
        model.train()
        train_loss = 0.0
        for X_batch, y_batch in train_loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            
            optimizer.zero_grad()
            outputs = model(X_batch)
            loss = criterion(outputs, y_batch)
            loss.backward()
            optimizer.step()
            
            train_loss += loss.item()
        
        # Validation
        model.eval()
        val_loss = 0.0
        all_preds = []
        all_labels = []
        
        with torch.no_grad():
            for X_batch, y_batch in val_loader:
                X_batch, y_batch = X_batch.to(device), y_batch.to(device)
                outputs = model(X_batch)
                loss = criterion(outputs, y_batch)
                val_loss += loss.item()
                
                _, preds = torch.max(outputs, 1)
                all_preds.extend(preds.cpu().numpy())
                all_labels.extend(y_batch.cpu().numpy())
        
        train_loss /= len(train_loader)
        val_loss /= len(val_loader)
        
        scheduler.step(val_loss)
        
        # Early stopping
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_model_state = model.state_dict().copy()
            patience_counter = 0
        else:
            patience_counter += 1
        
        if (epoch + 1) % 10 == 0:
            f1 = f1_score(all_labels, all_preds, average='binary')
            print(f"Epoch {epoch+1}/{epochs} - Train Loss: {train_loss:.4f}, Val Loss: {val_loss:.4f}, F1: {f1:.4f}")
        
        if patience_counter >= max_patience:
            print(f"Early stopping at epoch {epoch+1}")
            break
    
    # Load best model
    model.load_state_dict(best_model_state)
    
    # Final evaluation
    model.eval()
    all_preds = []
    all_labels = []
    all_probs = []
    
    with torch.no_grad():
        for X_batch, y_batch in val_loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            outputs = model(X_batch)
            probs = torch.softmax(outputs, dim=1)
            
            _, preds = torch.max(outputs, 1)
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(y_batch.cpu().numpy())
            all_probs.extend(probs[:, 1].cpu().numpy())
    
    metrics = {
        'accuracy': accuracy_score(all_labels, all_preds),
        'precision': precision_score(all_labels, all_preds, average='binary'),
        'recall': recall_score(all_labels, all_preds, average='binary'),
        'f1': f1_score(all_labels, all_preds, average='binary'),
        'roc_auc': roc_auc_score(all_labels, all_probs)
    }
    
    return model, metrics


def evaluate_model_on_test(model, test_loader, device='cuda' if torch.cuda.is_available() else 'cpu'):
    """테스트 데이터에서 모델 평가"""
    model.eval()
    all_preds = []
    all_labels = []
    all_probs = []
    
    with torch.no_grad():
        for X_batch, y_batch in test_loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            outputs = model(X_batch)
            probs = torch.softmax(outputs, dim=1)
            
            _, preds = torch.max(outputs, 1)
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(y_batch.cpu().numpy())
            all_probs.extend(probs[:, 1].cpu().numpy())
    
    return np.array(all_preds), np.array(all_labels), np.array(all_probs)


# ==================== 메인 학습 프로세스 ====================
def main():
    print("=" * 80)
    print("랜섬웨어 탐지 다중 모델 학습 및 비교 시스템")
    print("=" * 80)
    
    # 1. 데이터 로딩
    print(f"\n[1] 데이터 로딩: {CSV_PATH}")
    df = pd.read_csv(CSV_PATH)
    
    # 필수 컬럼 체크
    required_cols = {"GR", "ID", "filename", "family"}
    missing_req = [c for c in required_cols if c not in df.columns]
    if missing_req:
        raise ValueError(f"CSV에 필수 컬럼이 없습니다: {missing_req}")
    
    # 바이트 피처 수집
    byte_cols = sorted([c for c in df.columns if c.isdigit()], key=lambda x: int(x))
    print(f"    원본 바이트 피처 개수: {len(byte_cols)}")
    
    # 라벨/피처 분리
    y = df["GR"].astype(int).values
    X_raw = df[byte_cols].astype(float)
    
    print(f"    총 샘플 수: {len(y)}")
    print(f"    정상: {(y==0).sum()}, 랜섬웨어: {(y==1).sum()}")
    
    # 2. 피처 선택
    print("\n[2] 피처 선택 (Variance Threshold + Random Forest)")
    vt = VarianceThreshold(threshold=0.0)
    X_vt = vt.fit_transform(X_raw)
    kept_features = [c for c, keep in zip(byte_cols, vt.get_support()) if keep]
    print(f"    상수 피처 제거 후: {len(kept_features)} 개")
    
    # RF로 피처 중요도 계산
    rf_fs = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample"
    )
    rf_fs.fit(X_vt, y)
    importances = rf_fs.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    
    K = min(TOP_K_FEATURES, len(kept_features))
    selected_indices = sorted_idx[:K]
    selected_features = [kept_features[i] for i in selected_indices]
    
    print(f"    Top-{K} 피처 선택 완료")
    print(f"    상위 20개: {selected_features[:20]}")
    
    X_sel = X_vt[:, selected_indices]
    
    # 3. Train/Val/Test 분할
    print("\n[3] 데이터 분할 (Train 60% / Val 20% / Test 20%)")
    X_train, X_temp, y_train, y_temp = train_test_split(
        X_sel, y, test_size=0.4, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
    )
    
    print(f"    Train: {len(y_train)}, Val: {len(y_val)}, Test: {len(y_test)}")
    
    # 4. 모델 학습 및 평가
    results = {}
    
    # ========== Random Forest ==========
    print("\n" + "=" * 80)
    print("[4-1] Random Forest 학습")
    print("=" * 80)
    
    rf_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample"
    )
    rf_model.fit(X_train, y_train)
    
    # Test 평가
    y_pred_rf = rf_model.predict(X_test)
    y_proba_rf = rf_model.predict_proba(X_test)[:, 1]
    
    results['Random Forest'] = {
        'accuracy': accuracy_score(y_test, y_pred_rf),
        'precision': precision_score(y_test, y_pred_rf, average='binary'),
        'recall': recall_score(y_test, y_pred_rf, average='binary'),
        'f1': f1_score(y_test, y_pred_rf, average='binary'),
        'roc_auc': roc_auc_score(y_test, y_proba_rf)
    }
    
    print("\n[Random Forest 테스트 결과]")
    for metric, value in results['Random Forest'].items():
        print(f"    {metric}: {value:.4f}")
    
    # ========== CNN ==========
    print("\n" + "=" * 80)
    print("[4-2] CNN 학습")
    print("=" * 80)
    
    # DataLoader 생성
    train_dataset = HeaderDataset(X_train, y_train)
    val_dataset = HeaderDataset(X_val, y_val)
    test_dataset = HeaderDataset(X_test, y_test)
    
    train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=64, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=64, shuffle=False)
    
    cnn_model = HeaderCNN(input_size=K)
    cnn_model, _ = train_pytorch_model(cnn_model, train_loader, val_loader, epochs=50)
    
    # Test 평가
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    cnn_model = cnn_model.to(device)
    y_pred_cnn, y_true_cnn, y_proba_cnn = evaluate_model_on_test(cnn_model, test_loader, device)
    
    results['CNN'] = {
        'accuracy': accuracy_score(y_true_cnn, y_pred_cnn),
        'precision': precision_score(y_true_cnn, y_pred_cnn, average='binary'),
        'recall': recall_score(y_true_cnn, y_pred_cnn, average='binary'),
        'f1': f1_score(y_true_cnn, y_pred_cnn, average='binary'),
        'roc_auc': roc_auc_score(y_true_cnn, y_proba_cnn)
    }
    
    print("\n[CNN 테스트 결과]")
    for metric, value in results['CNN'].items():
        print(f"    {metric}: {value:.4f}")
    
    # ========== Transformer ==========
    print("\n" + "=" * 80)
    print("[4-3] Transformer 학습")
    print("=" * 80)
    
    transformer_model = HeaderTransformer(input_size=K)
    transformer_model, _ = train_pytorch_model(transformer_model, train_loader, val_loader, epochs=50)
    
    # Test 평가
    transformer_model = transformer_model.to(device)
    y_pred_trans, y_true_trans, y_proba_trans = evaluate_model_on_test(transformer_model, test_loader, device)
    
    results['Transformer'] = {
        'accuracy': accuracy_score(y_true_trans, y_pred_trans),
        'precision': precision_score(y_true_trans, y_pred_trans, average='binary'),
        'recall': recall_score(y_true_trans, y_pred_trans, average='binary'),
        'f1': f1_score(y_true_trans, y_pred_trans, average='binary'),
        'roc_auc': roc_auc_score(y_true_trans, y_proba_trans)
    }
    
    print("\n[Transformer 테스트 결과]")
    for metric, value in results['Transformer'].items():
        print(f"    {metric}: {value:.4f}")
    
    # 5. 결과 비교 및 저장
    print("\n" + "=" * 80)
    print("[5] 최종 모델 성능 비교")
    print("=" * 80)
    
    comparison_df = pd.DataFrame(results).T
    comparison_df = comparison_df.round(4)
    print("\n", comparison_df)
    
    # 최고 성능 모델
    best_model = comparison_df['f1'].idxmax()
    print(f"\n🏆 최고 F1 Score 모델: {best_model} (F1: {comparison_df.loc[best_model, 'f1']:.4f})")
    
    # 6. 모델 및 메타데이터 저장
    print("\n[6] 모델 및 메타데이터 저장")
    
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    # Random Forest 저장
    joblib.dump(rf_model, MODEL_PATH)
    print(f"    ✅ Random Forest 저장: {MODEL_PATH}")
    
    # CNN 저장
    cnn_path = MODEL_PATH.parent / "ransom_cnn.pth"
    torch.save(cnn_model.state_dict(), cnn_path)
    print(f"    ✅ CNN 저장: {cnn_path}")
    
    # Transformer 저장
    trans_path = MODEL_PATH.parent / "ransom_transformer.pth"
    torch.save(transformer_model.state_dict(), trans_path)
    print(f"    ✅ Transformer 저장: {trans_path}")
    
    # 피처 목록 저장
    FEATURES_PATH.write_text(
        json.dumps(selected_features, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    print(f"    ✅ 피처 목록 저장: {FEATURES_PATH}")
    
    # 정상 파일 통계 저장
    benign = df[df["GR"] == 0]
    stats = {}
    for name in selected_features:
        col = benign[name].astype(float)
        stats[name] = {
            "mean": float(col.mean()),
            "std": float(col.std(ddof=0) or 1e-6)
        }
    
    BENIGN_STATS_PATH.write_text(
        json.dumps(stats, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    print(f"    ✅ 정상 파일 통계 저장: {BENIGN_STATS_PATH}")
    
    # 성능 비교 결과 저장
    comparison_path = MODEL_PATH.parent / "model_comparison.json"
    comparison_dict = {
        'models': results,
        'best_model': best_model,
        'feature_count': K,
        'dataset_info': {
            'total_samples': len(y),
            'benign': int((y == 0).sum()),
            'ransomware': int((y == 1).sum()),
            'train_size': len(y_train),
            'val_size': len(y_val),
            'test_size': len(y_test)
        }
    }
    
    comparison_path.write_text(
        json.dumps(comparison_dict, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    print(f"    ✅ 성능 비교 결과 저장: {comparison_path}")
    
    print("\n" + "=" * 80)
    print("✅ 모든 학습 및 평가 완료!")
    print("=" * 80)


if __name__ == "__main__":
    main()