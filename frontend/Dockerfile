FROM python:3.11-slim

# Optimasi internal Python di dalam container
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /workspace

# Install system dependencies yang esensial jika diperlukan nantinya
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Pemanfaatan Docker cache layer untuk pip requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy seluruh source code aplikasi
COPY . .

# Expose default port Streamlit
EXPOSE 8501

# Jalankan Streamlit dengan bind ke seluruh interface internet container
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
