import os
import time
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, classification_report

def load_data():
    """Load the training Parquet dataset from the shared directory."""
    if os.path.exists("/workspace/data/train.parquet"):
        path = "/workspace/data/train.parquet"
    else:
        path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data/train.parquet"))
        
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset not found at {path}. Please run generator.py first!")
        
    print(f"Loading training dataset from {path}...")
    return pd.read_parquet(path)

def rule_based_veto(df):
    """
    Apply Rule-Based Veto:
    If OUT_BYTES > 50000 and IN_BYTES < 5000, immediately classify as Benign.
    Returns a boolean mask where True indicates the row is vetoed (automatically Benign).
    """
    return (df["OUT_BYTES"] > 50000) & (df["IN_BYTES"] < 5000)

def predict_hybrid(X_eval, model):
    """
    Predict labels using the hybrid pipeline.
    - If veto rule matches: predict 'Benign' (ML bypass).
    - Else: predict using Random Forest model.
    """
    veto_mask = rule_based_veto(X_eval)
    
    # Initialize prediction array
    hybrid_preds = np.empty(len(X_eval), dtype=object)
    
    # Fill vetoed rows with 'Benign'
    hybrid_preds[veto_mask] = "Benign"
    
    # Infer using ML model for non-vetoed rows
    non_veto_indices = ~veto_mask
    if non_veto_indices.any():
        X_ml = X_eval[non_veto_indices]
        ml_preds = model.predict(X_ml)
        hybrid_preds[non_veto_indices] = ml_preds
        
    return hybrid_preds

def evaluate_hybrid_pipeline(X_eval, y_eval, model):
    """
    Evaluates the hybrid pipeline performance on a test dataset.
    """
    hybrid_preds = predict_hybrid(X_eval, model)
    accuracy = accuracy_score(y_eval, hybrid_preds)
    f1_macro = f1_score(y_eval, hybrid_preds, average="macro")
    
    return hybrid_preds, accuracy, f1_macro

if __name__ == "__main__":
    start_time = time.time()
    
    print("==================================================")
    print("      NETFLOW L4 HYBRID DETECTION ENGINE          ")
    print("==================================================")
    
    # 1. Load Parquet Data
    try:
        df = load_data()
    except FileNotFoundError as e:
        print(f"Error: {e}")
        exit(1)
        
    # Define features and target
    features = ["PROTOCOL", "L4_DST_PORT", "IN_BYTES", "OUT_BYTES", "IN_PKTS", "TCP_FLAGS", "FLOW_DURATION"]
    target = "LABEL"
    
    X = df[features]
    y = df[target]
    
    # 2. Train-Test Split (80:20)
    print("\nSplitting dataset (80:20 training/testing)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 3. Train Machine Learning Model (Random Forest)
    print("Training Random Forest Classifier on training split...")
    rf_start = time.time()
    
    # Keeping it simple as per constraints (no complex hyperparameter tuning)
    model = RandomForestClassifier(n_estimators=50, max_depth=12, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    
    rf_duration = time.time() - rf_start
    print(f"Random Forest model training completed in {rf_duration:.2f} seconds.")
    
    # 4. Evaluate Pipeline (Hybrid: Rule-Based Veto + ML)
    print("\nEvaluating Hybrid Triage & ML Pipeline...")
    preds, accuracy, f1_macro = evaluate_hybrid_pipeline(X_test, y_test, model)
    
    print("\n================ EVALUATION REPORT ================")
    print(f"Pipeline Accuracy : {accuracy * 100:.4f}%")
    print(f"Pipeline F1-Score : {f1_macro * 100:.4f}% (Macro Average)")
    print("--------------------------------------------------")
    print("Detailed Classification Report:")
    print(classification_report(y_test, preds, digits=4))
    print("==================================================")
    
    # 5. Export Model & Weights
    # Set output directory dynamically (volume mounts)
    if os.path.exists("/workspace"):
        models_dir = "/workspace/models"
    else:
        models_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../models"))
        
    os.makedirs(models_dir, exist_ok=True)
    model_path = os.path.join(models_dir, "netflow_rf_model.joblib")
    
    print(f"\nExporting trained model object to {model_path}...")
    joblib.dump(model, model_path, compress=3)

    # 6. Sanity Check Otomatis (Uji Coba Inferensi Manual)
    print("\nRunning Automatic Sanity Checks...")
    
    # Paket 1: DDoS (1500 pkts, 40 bytes input, port 80, TCP flags SYN=2)
    sample_ddos = pd.DataFrame([{
        "PROTOCOL": 6, "L4_DST_PORT": 80, "IN_BYTES": 40, "OUT_BYTES": 0,
        "IN_PKTS": 1500, "TCP_FLAGS": 2, "FLOW_DURATION": 10.0
    }])
    
    # Paket 2: Benign (vetoed download: OUT_BYTES > 50000 and IN_BYTES < 5000)
    sample_benign = pd.DataFrame([{
        "PROTOCOL": 6, "L4_DST_PORT": 443, "IN_BYTES": 1000, "OUT_BYTES": 100000,
        "IN_PKTS": 10, "TCP_FLAGS": 16, "FLOW_DURATION": 1500.0
    }])
    
    # Predict using the hybrid pipeline
    pred_ddos = predict_hybrid(sample_ddos, model)
    pred_benign = predict_hybrid(sample_benign, model)
    
    print(f"  - Test Paket 1 (DDoS): Predicted = '{pred_ddos[0]}' (Expected: 'DDoS')")
    print(f"  - Test Paket 2 (Benign): Predicted = '{pred_benign[0]}' (Expected: 'Benign')")
    
    # Assert correctness programmatically
    assert pred_ddos[0] == "DDoS", f"Sanity check failed: DDoS was predicted as {pred_ddos[0]}"
    assert pred_benign[0] == "Benign", f"Sanity check failed: Benign was predicted as {pred_benign[0]}"
    print("Sanity checks PASSED successfully!")
    
    total_duration = time.time() - start_time
    print(f"\nSUCCESS: Engine pipeline completed in {total_duration:.2f} seconds!")
    print("==================================================")
