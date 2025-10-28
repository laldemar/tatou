# Server image: Flask + RMAP (needs gpg)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# --- OS deps: RMAP shells out to gpg ---
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      gnupg dirmngr ca-certificates git openssh-client tzdata \
 && rm -rf /var/lib/apt/lists/*

# --- Python deps ---
# Prefer requirements.txt (simpler + stable)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# --- App sources (everything under server/) ---
# This will copy: server.py, entrypoint.sh, keys/, logs/, etc.
COPY . /app

# Make sure entrypoint is executable
RUN chmod +x /app/entrypoint.sh

EXPOSE 5000
CMD ["./entrypoint.sh"]
