import os
import time
import numpy as np
import pandas as pd

def generate_netflow_chunk(num_rows, has_label=True, seed=42):
    """
    Generates a realistic synthetic NetFlow V1 dataset using vectorized NumPy operations.
    Proportions:
    - Benign: 60%
    - DDoS Flood: 15%
    - Port Scanning: 15%
    - Brute Force: 10%
    """
    np.random.seed(seed)
    
    n_benign = int(num_rows * 0.60)
    n_ddos = int(num_rows * 0.15)
    n_portscan = int(num_rows * 0.15)
    n_bruteforce = num_rows - n_benign - n_ddos - n_portscan

    print(f"Allocating distributions for {num_rows:,} rows:")
    print(f"  - Benign: {n_benign:,} rows")
    print(f"  - DDoS Flood: {n_ddos:,} rows")
    print(f"  - Port Scanning: {n_portscan:,} rows")
    print(f"  - Brute Force: {n_bruteforce:,} rows")

    # Pools of source IPs
    local_ips = [f"192.168.10.{i}" for i in range(2, 102)]      # 100 legitimate local IPs
    clean_public_ips = [f"8.8.8.{i}" for i in range(1, 10)] + [f"1.1.1.{i}" for i in range(1, 10)]
    benign_ip_pool = local_ips + clean_public_ips
    
    ddos_ip_pool = [f"185.220.101.{i}" for i in range(1, 101)] # DDoS attackers pool
    bf_ip_pool = [f"195.154.120.{i}" for i in range(1, 6)]     # Consistent 5 brute-forcers
    scan_ip_pool = [f"45.227.254.{i}" for i in range(1, 16)]   # 15 port scanners

    # 1. GENERATE BENIGN TRAFFIC
    print("Generating Benign Traffic...")
    benign_df = pd.DataFrame()
    benign_df["IPV4_SRC_ADDR"] = np.random.choice(benign_ip_pool, size=n_benign)
    benign_df["PROTOCOL"] = np.random.choice([6, 17], size=n_benign, p=[0.7, 0.3])
    
    # Ports: 80/443 for web (75%), 53/123 for DNS/NTP (15%), random high ports (10%)
    ports = np.random.randint(1024, 65535, size=n_benign)
    web_mask = np.random.rand(n_benign) < 0.75
    ports[web_mask] = np.random.choice([80, 443], size=sum(web_mask))
    dns_mask = (~web_mask) & (benign_df["PROTOCOL"] == 17) & (np.random.rand(n_benign) < 0.5)
    ports[dns_mask] = np.random.choice([53, 123], size=sum(dns_mask))
    benign_df["L4_DST_PORT"] = ports
    
    benign_df["IN_PKTS"] = np.random.randint(5, 500, size=n_benign)
    in_bytes = benign_df["IN_PKTS"] * np.random.randint(64, 1500, size=n_benign)
    benign_df["IN_BYTES"] = in_bytes
    
    # Out bytes: download vs balanced traffic
    download_mask = np.random.rand(n_benign) < 0.4
    out_bytes = in_bytes.copy()
    out_bytes[download_mask] = in_bytes[download_mask] * np.random.randint(5, 50, size=sum(download_mask))
    out_bytes[~download_mask] = (in_bytes[~download_mask] * np.random.uniform(0.8, 1.2, size=sum(~download_mask))).astype(int)
    benign_df["OUT_BYTES"] = out_bytes
    
    # TCP Flags: 16 (ACK), 1 (FIN), 17 (FIN-ACK)
    flags = np.zeros(n_benign, dtype=int)
    tcp_mask = benign_df["PROTOCOL"] == 6
    flags[tcp_mask] = np.random.choice([16, 1, 17], size=sum(tcp_mask), p=[0.8, 0.1, 0.1])
    benign_df["TCP_FLAGS"] = flags
    benign_df["FLOW_DURATION"] = np.random.uniform(50.0, 60000.0, size=n_benign)
    if has_label:
        benign_df["LABEL"] = "Benign"

    # 2. GENERATE DDOS FLOOD TRAFFIC
    print("Generating DDoS Flood Traffic...")
    ddos_df = pd.DataFrame()
    ddos_df["IPV4_SRC_ADDR"] = np.random.choice(ddos_ip_pool, size=n_ddos)
    ddos_df["PROTOCOL"] = np.ones(n_ddos, dtype=int) * 6 # TCP
    ddos_df["L4_DST_PORT"] = np.random.choice([80, 443], size=n_ddos, p=[0.6, 0.4])
    ddos_df["IN_PKTS"] = np.random.randint(1000, 10000, size=n_ddos) # high quantity packets (>= 1000)
    # Generate bytes with noise to prevent collinearity and force model to split on IN_PKTS
    in_bytes = ddos_df["IN_PKTS"] * 64
    noise_mask = np.random.rand(n_ddos) < 0.10 # 10% anomalous low bytes for DDoS
    in_bytes[noise_mask] = np.random.randint(40, 300, size=sum(noise_mask))
    ddos_df["IN_BYTES"] = in_bytes
    ddos_df["OUT_BYTES"] = np.zeros(n_ddos, dtype=int)
    ddos_df["TCP_FLAGS"] = np.ones(n_ddos, dtype=int) * 2 # SYN (2)
    ddos_df["FLOW_DURATION"] = np.random.uniform(0.1, 499.0, size=n_ddos) # very short duration (< 500 ms)
    if has_label:
        ddos_df["LABEL"] = "DDoS"

    # 3. GENERATE PORT SCANNING TRAFFIC
    print("Generating Port Scanning Traffic...")
    scan_df = pd.DataFrame()
    scan_df["IPV4_SRC_ADDR"] = np.random.choice(scan_ip_pool, size=n_portscan)
    scan_df["PROTOCOL"] = np.ones(n_portscan, dtype=int) * 6 # TCP
    scan_df["L4_DST_PORT"] = np.random.randint(1, 65535, size=n_portscan)
    scan_df["IN_PKTS"] = np.random.randint(1, 6, size=n_portscan) # strictly 1 to 5 packets
    scan_df["IN_BYTES"] = scan_df["IN_PKTS"] * np.random.randint(40, 55, size=n_portscan) # very small (< 300 bytes)
    scan_df["OUT_BYTES"] = np.zeros(n_portscan, dtype=int)
    scan_df["TCP_FLAGS"] = np.ones(n_portscan, dtype=int) * 2 # SYN (2)
    scan_df["FLOW_DURATION"] = np.random.uniform(0.1, 10.0, size=n_portscan)
    if has_label:
        scan_df["LABEL"] = "Port Scanning"

    # 4. GENERATE BRUTE FORCE TRAFFIC
    print("Generating Brute Force Traffic...")
    bf_df = pd.DataFrame()
    bf_df["IPV4_SRC_ADDR"] = np.random.choice(bf_ip_pool, size=n_bruteforce)
    bf_df["PROTOCOL"] = np.ones(n_bruteforce, dtype=int) * 6 # TCP
    bf_df["L4_DST_PORT"] = np.ones(n_bruteforce, dtype=int) * 22 # SSH
    bf_df["IN_PKTS"] = np.random.randint(15, 50, size=n_bruteforce) # Small consistent packets
    bf_df["IN_BYTES"] = bf_df["IN_PKTS"] * np.random.randint(60, 120, size=n_bruteforce)
    bf_df["OUT_BYTES"] = np.random.randint(500, 2500, size=n_bruteforce) # small payload response
    bf_df["TCP_FLAGS"] = np.random.choice([16, 24], size=n_bruteforce, p=[0.8, 0.2]) # ACK (16) or PSH-ACK (24)
    bf_df["FLOW_DURATION"] = np.random.uniform(500.0, 3000.0, size=n_bruteforce) # short connection
    if has_label:
        bf_df["LABEL"] = "Brute Force"

    # Concatenate & Shuffle
    print("Merging and shuffling dataset...")
    full_df = pd.concat([benign_df, ddos_df, scan_df, bf_df], ignore_index=True)
    full_df = full_df.sample(frac=1.0, random_state=seed).reset_index(drop=True)

    return full_df

if __name__ == "__main__":
    start_time = time.time()
    
    # Path output (akan disimpan ke volume sharing data/)
    if os.path.exists("/workspace"):
        data_dir = "/workspace/data"
    else:
        # Fallback to local data directory in workspace root when running on host
        data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data"))
        
    os.makedirs(data_dir, exist_ok=True)
    
    train_path = os.path.join(data_dir, "train.parquet")
    live_path = os.path.join(data_dir, "live.parquet")
    
    print("==================================================")
    print("   NETFLOW V1 SYNTHETIC TELEMETRY GENERATOR       ")
    print("==================================================")
    
    # 1. Generate 400,000 training rows (labeled)
    print("\n--- Phase 1: Generating Labeled Training Dataset (400k) ---")
    train_df = generate_netflow_chunk(400000, has_label=True, seed=42)
    print(f"Writing to {train_path}...")
    train_df.to_parquet(train_path, index=False, compression="snappy")
    print("Phase 1 Complete.")
    
    # 2. Generate 100,000 live dashboard rows (unlabeled)
    print("\n--- Phase 2: Generating Unlabeled Live Stream Dataset (100k) ---")
    live_df = generate_netflow_chunk(100000, has_label=False, seed=43)
    print(f"Writing to {live_path}...")
    live_df.to_parquet(live_path, index=False, compression="snappy")
    print("Phase 2 Complete.")
    
    elapsed_time = time.time() - start_time
    print("==================================================")
    print(f"SUCCESS: Generated 500k total NetFlow rows in {elapsed_time:.2f} seconds!")
    print(f"Train Dataset: {train_path} ({os.path.getsize(train_path)/1024/1024:.2f} MB)")
    print(f"Live Dataset : {live_path} ({os.path.getsize(live_path)/1024/1024:.2f} MB)")
    print("==================================================")
