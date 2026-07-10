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

# Copy seluruh source code backend
COPY . .

# Buat directory data jika belum ada
RUN mkdir -p /workspace/data

# Jalankan generator.py dan engine.py, lalu biarkan container running agar bisa digunakan untuk tugas ML berikutnya
CMD python generator.py && python engine.py && tail -f /dev/null
