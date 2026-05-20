# Cloud Run 向け Dockerfile（linux/amd64 を推奨）
# - Streamlit UI + trivy + Maven + Node/npm + uv/pipenv を同梱
# - Cloud Run の PORT 環境変数に従って待受けします

FROM aquasec/trivy:0.69.3 AS trivy

FROM python:3.11-slim AS app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# OS 依存ツールの導入（Java/Maven/Node/npm）
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip git \
        openjdk-21-jre-headless maven \
        nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# trivy を公式イメージからコピー
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

# trivy のDB更新を抑止（SBOM目的の場合のネットワーク依存低減）
ENV TRIVY_SKIP_DB_UPDATE=true \
    TRIVY_SKIP_JAVA_DB_UPDATE=true

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# アプリ一式
COPY . /app

# Cloud Run は既定で 8080 に送る。Streamlit を PORT に合わせる
ENV PORT=8080
EXPOSE 8080

# AWS の要件: 0.0.0.0 で待受け（127.0.0.1 は不可）
CMD ["bash", "-lc", "streamlit run streamlit_app.py   --server.address=0.0.0.0   --server.port=${PORT:-8080}   --server.headless=true   --server.enableCORS=false   --server.enableXsrfProtection=false   --server.baseUrlPath=${STREAMLIT_BASE_URL_PATH:-sbom-tool}"]