import os
import sys
import joblib
import pandas as pd
import numpy as np

# Column names used by the model
FEATURES = ["PROTOCOL", "L4_DST_PORT", "IN_BYTES", "OUT_BYTES", "IN_PKTS", "TCP_FLAGS", "FLOW_DURATION"]

def print_cheat_sheet():
    """Prints a reference guide to help the user simulate network traffic scenarios."""
    print("""
======================================================================
               🔍 NETFLOW TRAFFIC GENERATION CHEAT SHEET             
======================================================================
1. 🚨 DDoS Flood:
   - PROTOCOL: 6 (TCP)
   - IN_PKTS: Massive (>= 1000)
   - FLOW_DURATION: Short (< 500 ms)
   - OUT_BYTES: 0
   - TCP_FLAGS: 2 (SYN)

2. 🚪 Port Scanning:
   - PROTOCOL: 6 (TCP)
   - IN_PKTS: Small (1 - 5 packets)
   - IN_BYTES: Small (< 300 bytes)
   - OUT_BYTES: 0
   - TCP_FLAGS: 2 (SYN)

3. 🔑 Brute Force:
   - L4_DST_PORT: 22 (SSH)
   - PROTOCOL: 6 (TCP)
   - IN_PKTS: Consistent small packets (e.g. 15-50)
   - IN_BYTES: Small (e.g. 1000 - 3000 bytes)
   - OUT_BYTES: Small SSH responses (e.g. 500 - 2000 bytes)

4. 🛡️ Benign (Normal Traffic or Legitimate Downloads):
   - Outbound Veto: OUT_BYTES > 50000 AND IN_BYTES < 5000 (Automatic Veto)
   - Normal traffic: Balanced IN_BYTES and OUT_BYTES

* Type 'exit' at any prompt to quit the validator safely.
======================================================================
""")

def load_rf_model():
    """Loads the trained Random Forest model dynamically."""
    paths_to_try = [
        os.path.abspath(os.path.join(os.path.dirname(__file__), "models/netflow_rf_model.joblib")),
        "/workspace/models/netflow_rf_model.joblib"
    ]
    
    model = None
    loaded_path = ""
    for path in paths_to_try:
        if os.path.exists(path):
            try:
                model = joblib.load(path)
                loaded_path = path
                break
            except Exception as e:
                print(f"⚠️ Error loading model from {path}: {e}")
                
    if model is None:
        print("\n❌ CRITICAL ERROR: Model file 'netflow_rf_model.joblib' could not be found.")
        print("💡 Solution: You must train the model first by running the engine script:")
        print("   python3 backend/engine.py\n")
        sys.exit(1)
        
    print(f"✅ Successful: Loaded trained Random Forest model from:")
    print(f"   {loaded_path}")
    return model

def get_input(prompt_text, cast_type=int):
    """Safely reads and validates input from the user."""
    while True:
        try:
            val_str = input(prompt_text).strip()
            if val_str.lower() == "exit":
                print("\nExiting CLI Validator. Stay secure! 🛡️")
                sys.exit(0)
            return cast_type(val_str)
        except ValueError:
            expected_type = "integer" if cast_type == int else "decimal number"
            print(f"⚠️  Input Error: Please enter a valid {expected_type}.")

def rule_based_veto_check(in_bytes, out_bytes):
    """Applies the static bypass veto rule: OUT_BYTES > 50000 AND IN_BYTES < 5000."""
    return out_bytes > 50000 and in_bytes < 5000

if __name__ == "__main__":
    print("======================================================================")
    print("        🛡️  UNIFIED THREAT DETECTION (L4 STRESS TEST VALIDATOR)      ")
    print("======================================================================")
    
    # 1. Load the model
    model = load_rf_model()
    
    # 2. Show the Cheat Sheet
    print_cheat_sheet()
    
    # 3. Interactive Loop
    while True:
        print("\n--- Enter Traffic Telemetry to Validate ---")
        
        protocol = get_input("👉 PROTOCOL (6=TCP, 17=UDP): ", int)
        port = get_input("👉 L4_DST_PORT (e.g. 80, 443, 22): ", int)
        in_bytes = get_input("👉 IN_BYTES (Volumetric incoming bytes): ", int)
        out_bytes = get_input("👉 OUT_BYTES (Volumetric outgoing bytes): ", int)
        in_pkts = get_input("👉 IN_PKTS (Incoming packet count): ", int)
        tcp_flags = get_input("👉 TCP_FLAGS (e.g. 2=SYN, 16=ACK, 0=None): ", int)
        flow_duration = get_input("👉 FLOW_DURATION (Connection duration in ms): ", float)
        
        # Assemble input DataFrame
        input_data = pd.DataFrame([{
            "PROTOCOL": protocol,
            "L4_DST_PORT": port,
            "IN_BYTES": in_bytes,
            "OUT_BYTES": out_bytes,
            "IN_PKTS": in_pkts,
            "TCP_FLAGS": tcp_flags,
            "FLOW_DURATION": flow_duration
        }])
        
        print("\nRunning Triage...")
        
        # Apply Hybrid Detection
        is_vetoed = rule_based_veto_check(in_bytes, out_bytes)
        
        if is_vetoed:
            prediction = "Benign"
            detection_mechanism = "Rule-Based Veto (Bypassed ML)"
        else:
            # Predict using Random Forest
            prediction = model.predict(input_data)[0]
            detection_mechanism = "Machine Learning (Random Forest Inference)"
            
        # Format output display based on results
        if prediction == "Benign":
            badge = "🟢 [CLEAN TRAFFIC]"
            display_msg = f"No threats detected. Flow is safe."
        elif prediction == "DDoS":
            badge = "🚨 [CRITICAL THREAT]"
            display_msg = f"DDoS Volumetric Flood Attack detected!"
        elif prediction == "Port Scanning":
            badge = "🟡 [WARNING THREAT]"
            display_msg = f"Port Scanning/Reconnaissance probe detected!"
        elif prediction == "Brute Force":
            badge = "🔴 [HIGH THREAT]"
            display_msg = f"Brute Force Authentication Attack detected!"
        else:
            badge = "⚪ [UNKNOWN]"
            display_msg = f"Unusual traffic footprint detected."
            
        print("\n======================= ANALYSIS RESULTS =======================")
        print(f"  Result      : {badge} {prediction}")
        print(f"  Description : {display_msg}")
        print(f"  Mechanism   : {detection_mechanism}")
        print("================================================================")
