FROM python:3.11-slim

# 作業ディレクトリを設定
WORKDIR /app

# 余計なキャッシュを残さずにインストール
ENV PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

# 依存関係のみ先にコピーしてインストール
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# アプリコードと設定を取り込む
COPY . .
RUN mkdir -p downloaded_files

CMD ["python", "app.py"]
