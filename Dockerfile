FROM python:3.9-slim-bullseye
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends     gdal-bin     libgdal-dev     proj-bin     && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD gunicorn app:app --bind 0.0.0.0:${PORT} --worker-tmp-dir /dev/shm