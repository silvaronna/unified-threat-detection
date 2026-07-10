import os
import re
import time
import requests
import joblib
import pandas as pd
import numpy as np
import streamlit as st
import plotly.express as px
from datetime import datetime

# ==========================================
# PAGE CONFIGURATION & THEME STYLING
# ==========================================
st.set_page_config(
    page_title="Enterprise SOC Monitoring - NetFlow L4 Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Premium Grafana/Splunk Dark Mode styling
st.markdown("""
<style>
    .reportview-container {
        background: #0B0F19;
    }
    .metric-container {
        display: flex;
        justify-content: space-between;
        gap: 15px;
        margin-bottom: 25px;
    }
    .card-metric {
        background: #111827;
        border: 1px solid #1F2937;
        padding: 20px;
        border-radius: 8px;
        flex: 1;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    }
    .metric-title {
        color: #9CA3AF;
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        margin-bottom: 8px;
    }
    .metric-value {
        color: #F9FAFB;
        font-size: 1.8rem;
        font-weight: 700;
        line-height: 1;
    }
    .metric-sub {
        color: #9CA3AF;
        font-size: 0.70rem;
        margin-top: 5px;
    }
    .blue-border { border-left: 5px solid #3B82F6; }
    .red-border { border-left: 5px solid #EF4444; }
    .orange-border { border-left: 5px solid #F59E0B; }
    .green-border { border-left: 5px solid #10B981; }
</style>
""", unsafe_allow_html=True)

def df_to_markdown(df):
    """Custom light implementation of DataFrame.to_markdown() to avoid 'tabulate' dependency."""
    if df is None or df.empty:
        return ""
    headers = list(df.columns)
    lines = []
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for _, row in df.iterrows():
        row_str = [str(row[col]) for col in headers]
        lines.append("| " + " | ".join(row_str) + " |")
    return "\n".join(lines)

def df_to_compact_str(df):
    """Custom compact implementation to serialize DataFrame content for prompt optimization."""
    if df is None or df.empty:
        return "Tidak ada data."
    lines = []
    for _, row in df.iterrows():
        proto = "TCP" if row.get("PROTOCOL") == 6 else "UDP" if row.get("PROTOCOL") == 17 else str(row.get("PROTOCOL"))
        port = row.get("L4_DST_PORT")
        pkts = row.get("IN_PKTS")
        bytes_val = row.get("IN_BYTES")
        pred = row.get("PREDICTION")
        lines.append(f"- Proto: {proto}, Port: {port}, Pkts: {pkts}, Bytes: {bytes_val}, Pred: {pred}")
    return "\n".join(lines)

def get_ollama_stream(ollama_host, models_to_try, messages):
    """
    Tries to connect to Ollama Chat Completion API (/api/chat) and return a generator yielding tokens.
    If the first model fails or raises an error, tries the fallback model.
    """
    for model_name in models_to_try:
        try:
            payload = {
                "model": model_name,
                "messages": messages,
                "stream": True
            }
            # Start post with stream=True. Timeout of 180s is for connection establishment and initial model loading.
            response = requests.post(f"{ollama_host}/api/chat", json=payload, stream=True, timeout=180.0)
            if response.status_code == 200:
                def generator():
                    import json
                    for line in response.iter_lines():
                        if line:
                            chunk = json.loads(line.decode("utf-8"))
                            yield chunk.get("message", {}).get("content", "")
                return generator(), model_name
        except Exception as e:
            print(f"Ollama chat stream failed for {model_name}: {e}")
    return None, None


# ==========================================
# RESOURCE LOADERS & CACHING
# ==========================================
@st.cache_resource
def load_rf_model():
    """Loads the trained Random Forest model dynamically."""
    paths_to_try = [
        "/workspace/models/netflow_rf_model.joblib",
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../models/netflow_rf_model.joblib")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "models/netflow_rf_model.joblib"))
    ]
    for path in paths_to_try:
        if os.path.exists(path):
            try:
                return joblib.load(path)
            except Exception as e:
                st.sidebar.error(f"Error loading model from {path}: {e}")
    return None

@st.cache_data
def load_and_process_data(_model):
    """
    Loads the live Parquet dataset and applies the Hybrid Detection Engine:
    1. Rule-Based Veto (OUT_BYTES > 50000 and IN_BYTES < 5000)
    2. ML Inference (Random Forest) for non-vetoed data
    """
    paths_to_try = [
        "/workspace/data/live.parquet",
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../data/live.parquet")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "data/live.parquet"))
    ]
    df = None
    for path in paths_to_try:
        if os.path.exists(path):
            try:
                df = pd.read_parquet(path)
                break
            except Exception as e:
                st.sidebar.error(f"Error loading data from {path}: {e}")
                
    if df is None:
        return None

    # Apply hybrid prediction
    # 1. Rule Veto
    veto_mask = (df["OUT_BYTES"] > 50000) & (df["IN_BYTES"] < 5000)
    predictions = np.empty(len(df), dtype=object)
    predictions[veto_mask] = "Benign"
    
    # 2. ML Inference
    non_veto_mask = ~veto_mask
    if _model is not None and non_veto_mask.any():
        features = ["PROTOCOL", "L4_DST_PORT", "IN_BYTES", "OUT_BYTES", "IN_PKTS", "TCP_FLAGS", "FLOW_DURATION"]
        X_ml = df.loc[non_veto_mask, features]
        predictions[non_veto_mask] = _model.predict(X_ml)
    elif _model is None and non_veto_mask.any():
        predictions[non_veto_mask] = "Benign" # Fallback if model is missing
        
    df["PREDICTION"] = predictions
    return df

# ==========================================
# APP INITIALIZATION
# ==========================================
model = load_rf_model()
df_live = load_and_process_data(model)

if df_live is None:
    st.error("❌ live.parquet dataset could not be found.")
    st.info("Please generate the dataset first by running: `python3 backend/generator.py` and train the model with `python3 backend/engine.py`.")
    st.stop()

# ==========================================
# SIDEBAR CONTROLS
# ==========================================
with st.sidebar:
    st.image("https://img.icons8.com/color/96/shield.png", width=64)
    st.header("⚙️ SOC Control Panel")
    
    st.subheader("Interactive Filtering")
    threat_filter = st.selectbox(
        "Filter by Classification:",
        ["All Traffic", "Benign Only", "Attacks Only", "DDoS", "Port Scanning", "Brute Force"]
    )
    
    ip_search = st.text_input("🔍 Search IP Source Address:", value="")
    
    rows_to_show = st.slider("Display Limit (Preview Table):", min_value=10, max_value=1000, value=100, step=10)
    
    st.divider()
    st.subheader("System Status")
    if model is not None:
        st.success("🤖 Hybrid ML Model: Connected")
    else:
        st.warning("⚠️ ML Model: Not Connected (Using static veto rules only)")
        
    ollama_host = st.text_input("Local Ollama Host:", value="http://host.docker.internal:11434")
    llm_model = st.selectbox("Primary Local LLM:", ["qwen2.5:3b", "gemma2:2b"])
    
    if st.button("🔄 Reload Data & Refresh Cache"):
        st.cache_data.clear()
        st.rerun()

# Apply Filters to the Dataframe
if threat_filter == "Benign Only":
    df_filtered = df_live[df_live["PREDICTION"] == "Benign"]
elif threat_filter == "Attacks Only":
    df_filtered = df_live[df_live["PREDICTION"] != "Benign"]
elif threat_filter != "All Traffic":
    df_filtered = df_live[df_live["PREDICTION"] == threat_filter]
else:
    df_filtered = df_live

if ip_search.strip():
    df_filtered = df_filtered[df_filtered["IPV4_SRC_ADDR"].str.contains(ip_search.strip(), case=False, na=False)]

# Calculate General Statistics
total_flows = len(df_live)
total_attacks = sum(df_live["PREDICTION"] != "Benign")
triage_efficiency = (total_attacks / total_flows) * 100
saved_time_hours = (total_attacks * 5) / 3600

# ==========================================
# MULTI-TAB ARCHITECTURE LAYOUT
# ==========================================
tab_dashboard, tab_assistant = st.tabs(["📊 Live Security Dashboard", "💬 AI Security Assistant"])

# ==============================================================================
# TAB 1: LIVE SECURITY DASHBOARD
# ==============================================================================
with tab_dashboard:
    st.subheader("Real-Time Hybrid Threat Detection Pipeline")
    
    # 1. Top Metric Cards
    col_m1, col_m2, col_m3, col_m4 = st.columns(4)
    with col_m1:
        st.markdown(f"""
        <div class="card-metric blue-border">
            <div class="metric-title">Total Network Flows</div>
            <div class="metric-value">{total_flows:,}</div>
            <div class="metric-sub">Processed Live Telemetry</div>
        </div>
        """, unsafe_allow_html=True)
    with col_m2:
        st.markdown(f"""
        <div class="card-metric red-border">
            <div class="metric-title">Total Attacks Caught</div>
            <div class="metric-value">{total_attacks:,}</div>
            <div class="metric-sub">DDoS + Port Scan + Brute Force</div>
        </div>
        """, unsafe_allow_html=True)
    with col_m3:
        st.markdown(f"""
        <div class="card-metric orange-border">
            <div class="metric-title">Triage Efficiency</div>
            <div class="metric-value">{triage_efficiency:.2f}%</div>
            <div class="metric-sub">Anomalous Traffic Proportion</div>
        </div>
        """, unsafe_allow_html=True)
    with col_m4:
        st.markdown(f"""
        <div class="card-metric green-border">
            <div class="metric-title">Analyst Saved Time</div>
            <div class="metric-value">{saved_time_hours:.1f} Hrs</div>
            <div class="metric-sub">Estimated Automated Triage Time</div>
        </div>
        """, unsafe_allow_html=True)

    st.divider()

    # 2. Main Graphics Panel
    col_g1, col_g2 = st.columns([2, 3])
    
    with col_g1:
        st.subheader("📊 Threat Distribution")
        attacks_only = df_live[df_live["PREDICTION"] != "Benign"]
        if not attacks_only.empty:
            attack_counts = attacks_only["PREDICTION"].value_counts().reset_index()
            attack_counts.columns = ["Attack Type", "Count"]
            
            fig_donut = px.pie(
                attack_counts,
                names="Attack Type",
                values="Count",
                hole=0.45,
                color="Attack Type",
                color_discrete_map={
                    "DDoS": "#EF4444",
                    "Port Scanning": "#F59E0B",
                    "Brute Force": "#EC4899"
                }
            )
            fig_donut.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#F9FAFB",
                margin=dict(t=10, b=10, l=10, r=10),
                legend=dict(orientation="h", yanchor="bottom", y=-0.1, xanchor="center", x=0.5)
            )
            st.plotly_chart(fig_donut, use_container_width=True)
        else:
            st.info("No attacks detected in dataset.")

    with col_g2:
        st.subheader("📈 Attack Vector Characterization")
        benign_rows = df_live[df_live["PREDICTION"] == "Benign"]
        attack_rows = df_live[df_live["PREDICTION"] != "Benign"]
        sample_benign_count = max(500, 3000 - len(attack_rows))
        
        if len(benign_rows) > sample_benign_count:
            benign_rows = benign_rows.sample(n=sample_benign_count, random_state=42)
            
        sampled_plot_df = pd.concat([attack_rows, benign_rows])
        
        fig_scatter = px.scatter(
            sampled_plot_df,
            x="FLOW_DURATION",
            y="IN_PKTS",
            color="PREDICTION",
            size="IN_BYTES",
            hover_data=["PROTOCOL", "L4_DST_PORT", "OUT_BYTES"],
            color_discrete_map={
                "Benign": "#10B981",
                "DDoS": "#EF4444",
                "Port Scanning": "#F59E0B",
                "Brute Force": "#EC4899"
            },
            labels={"FLOW_DURATION": "Flow Duration (ms)", "IN_PKTS": "Incoming Packets (IN_PKTS)"}
        )
        fig_scatter.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#F9FAFB",
            margin=dict(t=20, b=10, l=10, r=10),
            xaxis=dict(gridcolor="#1F2937", title_font=dict(size=11)),
            yaxis=dict(gridcolor="#1F2937", title_font=dict(size=11))
        )
        st.plotly_chart(fig_scatter, use_container_width=True)

    st.divider()

    # 3. Interactive Data Table (Selection Mode enabled)
    st.subheader("📊 Live Log Interception View")
    st.write(f"Showing the latest {rows_to_show} filtered records. **Click on a row** to trigger LLM playbook generation and verify mitigations:")

    display_cols = ["IPV4_SRC_ADDR", "PROTOCOL", "L4_DST_PORT", "IN_BYTES", "OUT_BYTES", "IN_PKTS", "TCP_FLAGS", "FLOW_DURATION", "PREDICTION"]
    df_display = df_filtered[display_cols].head(rows_to_show).reset_index(drop=True)

    # Dynamic styling function based on classification
    def style_threat_level(val):
        if val == "DDoS":
            return 'background-color: #4A1525; color: #FF9EAF; font-weight: 500;'
        elif val == "Brute Force":
            return 'background-color: #4A2B15; color: #FFC09F; font-weight: 500;'
        elif val == "Port Scanning":
            return 'background-color: #4A3E15; color: #FFE09F; font-weight: 500;'
        elif val == "Benign":
            return 'background-color: #111827; color: #34D399;'
        return ''

    # Apply conditional colors
    df_styled = df_display.style.map(style_threat_level, subset=["PREDICTION"])
    
    # Selection Mode setup
    selection_event = st.dataframe(
        df_styled,
        use_container_width=True,
        on_select="rerun",
        selection_mode="single-row"
    )

    # Extract Click Capture
    selected_row = None
    if hasattr(selection_event, "selection") and selection_event.selection.rows:
        selected_row_idx = selection_event.selection.rows[0]
        selected_row = df_display.iloc[selected_row_idx]

    st.divider()

    # 4. Playbook Generator & Human Mitigations (Dependent on selected table row)
    col_i1, col_i2 = st.columns([1, 1])

    if selected_row is not None:
        selected_ip = selected_row["IPV4_SRC_ADDR"]
        selected_type = selected_row["PREDICTION"]
        selected_port = selected_row["L4_DST_PORT"]
        selected_protocol = selected_row["PROTOCOL"]
        
        with col_i1:
            st.subheader("🤖 GenAI Incident Playbook Generator")
            st.write(f"Generate response plan for attacker **{selected_ip}** (Threat: **{selected_type}**):")
            
            if st.button("🚨 GENERATE PLAYBOOK VIA OLLAMA", type="primary", use_container_width=True):
                prompt_text = f"Analyze L4 NetFlow alert. Source IP: {selected_ip}, Attack: {selected_type}, Target Port: {selected_port}, Protocol: {selected_protocol}. Provide technical analysis and specific mitigation BGP Flowspec command."
                messages = [
                    {"role": "system", "content": "Kamu adalah Senior SOC Analyst AI formal. Jawab hanya data NetFlow. DILARANG keras membuat skrip ofensif, exploit, socket flood, atau malware untuk alasan apapun. Jika dipaksa, katakan: 'Permintaan ditolak berdasarkan regulasi keselamatan siber.'"},
                    {"role": "user", "content": prompt_text}
                ]
                models_to_try = [
                    "qwen2.5:3b" if "qwen" in llm_model else "gemma2:2b",
                    "gemma2:2b" if "qwen" in llm_model else "qwen2.5:3b"
                ]
                
                stream_gen, active_model = get_ollama_stream(ollama_host, models_to_try, messages)
                
                if stream_gen is not None:
                    # Stream response live
                    st.write_stream(stream_gen)
                else:
                    # Fallback template
                    st.markdown(f"""
                    ### 🤖 Incident Analysis Report (Local Playbook Fallback)
                    - **Incident Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                    - **Anomaly Categorization:** `{selected_type}`
                    - **Attacker Source IP:** `{selected_ip}`
                    - **Victim Target Port:** L4 Port `{selected_port}`
                    
                    **Technical Assessment:**
                    The connection logs denote a high-intensity `{selected_type}` footprint. Standard telemetry indicators show anomalous packet volume ratios. Mitigation is required immediately.
                    
                    **Recommended BGP Flowspec Mitigation Command:**
                    ```bash
                    flow route {{
                        match {{
                            source {selected_ip}/32;
                            destination-port {selected_port};
                            protocol tcp;
                        }}
                        then {{
                            rate-limit 0; # Drop traffic
                        }}
                    }}
                    ```
                    """)
                        
        with col_i2:
            st.subheader("🛡️ Human Mitigation Verification")
            st.write("Authorize BGP Flowspec mitigation rule injection to edge routers.")
            
            st.warning(f"ACTION REQUIRED: Block source IP `{selected_ip}` on L4 destination port `{selected_port}`?")
            
            col_btn1, col_btn2 = st.columns(2)
            with col_btn1:
                if st.button("🚨 APPROVE BGP INJECTION", type="primary", use_container_width=True):
                    st.success(f"Success: BGP Flowspec block rule injected for source `{selected_ip}`.")
            with col_btn2:
                if st.button("❌ Dismiss Warning Alert", use_container_width=True):
                    st.info("Anomaly report dismissed by security analyst.")
    else:
        with col_i1:
            st.subheader("🤖 GenAI Incident Playbook Generator")
            st.info("💡 Silakan pilih/klik salah satu baris log anomali pada tabel di atas untuk memulai analisis.")
        with col_i2:
            st.subheader("🛡️ Human Mitigation Verification")
            st.info("💡 Silakan pilih/klik salah satu baris log anomali pada tabel di atas untuk memulai analisis.")

# ==============================================================================
# TAB 2: AI SECURITY ASSISTANT CHATBOT
# ==============================================================================
with tab_assistant:
    st.subheader("💬 AI Security Assistant Chatbot")
    st.write("Ask natural language questions about the telemetry, or run quick query filters using patterns.")

    # Initialize chat history
    if "messages" not in st.session_state:
        st.session_state.messages = [
            {
                "role": "assistant",
                "content": "Halo! Saya Senior SOC Assistant. Saya siap membantu Anda menganalisis log NetFlow L4 atau membuat visualisasi cepat. \n\n"
                           "💡 **Tips Perintah Cepat (Zero-Latency Router):**\n"
                           "- *tampilkan <N> ddos* atau *tampilkan <N> kritikal* (contoh: `tampilkan 5 ddos`)\n"
                           "- *cari <IP_ADDRESS>* atau *ip <IP_ADDRESS>* (contoh: `cari 185.220.101.4`)"
            }
        ]

    # Render history
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # User input
    user_input = st.chat_input("Tulis pertanyaan keamanan atau perintah analisis di sini...")

    if user_input:
        # Append and render user input
        st.session_state.messages.append({"role": "user", "content": user_input})
        with st.chat_message("user"):
            st.markdown(user_input)

        response_content = ""
        is_routed = False
        is_rendered = False

        # Pagar 0: Application-Level Security Check (Python Interceptor)
        blacklist = ['flood', 'exploit', 'malware', 'soket membanjiri', 'peras', 'hack', 'script ddos', 'membuat script ddos', 'socket.send']
        user_input_lower = user_input.lower()
        if any(term in user_input_lower for term in blacklist):
            response_content = "🚨 [SECURITY VIOLATION]: Permintaan diblokir oleh Application Guardrail Layer 0. Sistem mendeteksi parameter instruksi ofensif yang melanggar kebijakan keselamatan siber operasional SOC."
            is_routed = True

        # --- HYBRID CHATBOT ROUTER ---
        # Clean user input for strict matching
        cleaned_input = user_input.strip().lower()

        # 1. Regex Pattern 1 (Strict Anchor Line): tampilkan N [kritikal/ddos/brute force/scan]
        regex_show = re.search(r"^tampilkan\s+(\d+)\s+(kritikal|ddos|brute\s+force|scan)$", cleaned_input)
        
        # 2. Regex Pattern 2 (Strict Anchor Line): (ip|cari) IP_ADDRESS
        regex_ip = re.search(r"^(?:ip|cari)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", cleaned_input)

        if regex_show:
            is_routed = True
            count = int(regex_show.group(1))
            threat_type = regex_show.group(2)
            
            # Filter DataFrame
            if threat_type == "kritikal":
                df_res = df_live[df_live["PREDICTION"] != "Benign"].head(count)
                desc = "Serangan (DDoS / Port Scanning / Brute Force)"
            elif threat_type == "ddos":
                df_res = df_live[df_live["PREDICTION"] == "DDoS"].head(count)
                desc = "DDoS Flood"
            elif threat_type == "scan":
                df_res = df_live[df_live["PREDICTION"] == "Port Scanning"].head(count)
                desc = "Port Scanning"
            elif threat_type == "brute force":
                df_res = df_live[df_live["PREDICTION"] == "Brute Force"].head(count)
                desc = "Brute Force"
            else:
                df_res = df_live[df_live["PREDICTION"] == "Benign"].head(count)
                desc = "Benign (Bersih)"

            if not df_res.empty:
                response_content = f"Berikut adalah **{len(df_res)}** log berkategori **{desc}** terbaru dari database:\n\n"
                response_content += df_to_markdown(df_res[["IPV4_SRC_ADDR", "PROTOCOL", "L4_DST_PORT", "IN_PKTS", "IN_BYTES", "PREDICTION"]])
            else:
                response_content = f"Tidak ada data log dengan kategori **{desc}** yang ditemukan."

        elif regex_ip:
            is_routed = True
            target_ip = regex_ip.group(1)
            
            # Filter IP
            df_ip = df_live[df_live["IPV4_SRC_ADDR"] == target_ip]
            
            if not df_ip.empty:
                cnt_total = len(df_ip)
                cnt_ddos = sum(df_ip["PREDICTION"] == "DDoS")
                cnt_scan = sum(df_ip["PREDICTION"] == "Port Scanning")
                cnt_bf = sum(df_ip["PREDICTION"] == "Brute Force")
                cnt_benign = sum(df_ip["PREDICTION"] == "Benign")
                
                status = "🔴 ANOMALI TERDETEKSI" if (cnt_ddos + cnt_scan + cnt_bf) > 0 else "🟢 BERSIH (Benign)"
                
                response_content = (
                    f"### 🔍 Laporan Profil Ringkas IP Asal: `{target_ip}`\n"
                    f"- **Status Perimeter**: **{status}**\n"
                    f"- **Total Koneksi**: {cnt_total:,}\n"
                    f"  * DDoS Flood: {cnt_ddos:,}\n"
                    f"  * Port Scanning: {cnt_scan:,}\n"
                    f"  * Brute Force: {cnt_bf:,}\n"
                    f"  * Benign Traffic: {cnt_benign:,}\n\n"
                    "Rincian Log Koneksi Terakhir:\n\n"
                )
                response_content += df_to_markdown(df_ip[["PROTOCOL", "L4_DST_PORT", "IN_PKTS", "IN_BYTES", "PREDICTION"]].head(10))
            else:
                import difflib
                unique_ips = df_live["IPV4_SRC_ADDR"].unique().tolist()
                closest_matches = difflib.get_close_matches(target_ip, unique_ips, n=1, cutoff=0.0)
                recommendation = f" Mungkin maksud Anda: `{closest_matches[0]}`?" if closest_matches else ""
                response_content = f"❌ Alamat IP `{target_ip}` tidak ditemukan secara langsung di database log SOC.{recommendation}"

        # 3. Fallback: RAG Routing for Free-form Questions
        if not is_routed:
            with st.spinner("Analyzing request..."):
                # Step A: Detect if an IP address exists in the free-form question
                ip_extracted = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", user_input)
                
                # Step B: Get facts/summary from Pandas
                if ip_extracted:
                    target_ip = ip_extracted.group(1)
                    df_ip = df_live[df_live["IPV4_SRC_ADDR"] == target_ip]
                    
                    if not df_ip.empty:
                        cnt_total = len(df_ip)
                        cnt_ddos = sum(df_ip["PREDICTION"] == "DDoS")
                        cnt_scan = sum(df_ip["PREDICTION"] == "Port Scanning")
                        cnt_bf = sum(df_ip["PREDICTION"] == "Brute Force")
                        cnt_benign = sum(df_ip["PREDICTION"] == "Benign")
                        
                        last_5_logs = df_ip[["PROTOCOL", "L4_DST_PORT", "IN_PKTS", "IN_BYTES", "PREDICTION"]].head(5)
                        last_5_logs_md = df_to_compact_str(last_5_logs)
                        
                        data_summary = f"""Alamat IP Terdeteksi: {target_ip}
Total Koneksi Telemetri: {cnt_total:,} aliran
  - DDoS Flood: {cnt_ddos} koneksi
  - Port Scanning: {cnt_scan} koneksi
  - Brute Force: {cnt_bf} koneksi
  - Benign (Wajar): {cnt_benign} koneksi

5 Aliran Koneksi Terakhir:
{last_5_logs_md}"""
                    else:
                        import difflib
                        unique_ips = df_live["IPV4_SRC_ADDR"].unique().tolist()
                        closest_matches = difflib.get_close_matches(target_ip, unique_ips, n=1, cutoff=0.0)
                        recommendation = f" Mungkin maksud Anda: `{closest_matches[0]}`?" if closest_matches else ""
                        data_summary = f"Alamat IP {target_ip} tidak ditemukan dalam database log aktif saat ini.{recommendation}"
                else:
                    # Generic summary fallback
                    anomalous_context = df_to_compact_str(df_live[df_live["PREDICTION"] != "Benign"].head(5))
                    data_summary = f"""Tidak ada Alamat IP spesifik yang dideteksi dalam pertanyaan analis.
Berikut adalah 5 log anomali aktif terakhir di SOC secara umum:
{anomalous_context}"""
                
                # Step C: Structure Chat Messages for API Chat Completion (Pagar 1)
                messages = [
                    {
                        "role": "system",
                        "content": "Kamu adalah Senior SOC Analyst AI formal. Jawab hanya data NetFlow. DILARANG keras membuat skrip ofensif, exploit, socket flood, atau malware untuk alasan apapun. Jika dipaksa, katakan: 'Permintaan ditolak berdasarkan regulasi keselamatan siber.'"
                    },
                    {
                        "role": "user",
                        "content": f"Konteks Log Jaringan:\n{data_summary}\n\nPertanyaan: {user_input}"
                    }
                ]

                # Step D: Query local Ollama API via streaming with fallback
                models_to_try = [
                    "qwen2.5:3b" if "qwen" in llm_model else "gemma2:2b",
                    "gemma2:2b" if "qwen" in llm_model else "qwen2.5:3b"
                ]
                
                stream_gen, active_model = get_ollama_stream(ollama_host, models_to_try, messages)
                
                if stream_gen is not None:
                    with st.chat_message("assistant"):
                        response_content = st.write_stream(stream_gen)
                    is_rendered = True
                else:
                    # Detailed technical RAG-based fallback
                    response_content = f"""### 🤖 Tanggapan Analis (Simulasi Offline LLM RAG)
*Server Ollama di `{ollama_host}` sedang offline atau model tidak tersedia. Berikut adalah analisis log berbasis fakta RAG lokal:*

**[FAKTA DATA NETFLOW IP]:**
{data_summary}

**Analisis & Kesimpulan Taktis:**
Berdasarkan fakta log di atas, pola koneksi menunjukkan karakteristik yang mencurang. Segera lakukan audit mendalam pada IP yang terdeteksi dan lakukan mitigasi (seperti BGP Flowspec rate-limiting) pada perimeter network."""

        # Append and render assistant response
        st.session_state.messages.append({"role": "assistant", "content": response_content})
        if not is_rendered:
            with st.chat_message("assistant"):
                st.markdown(response_content)
