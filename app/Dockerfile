ARG MAVEN_IMAGE=maven:3.9.16-eclipse-temurin-25
ARG RUST_IMAGE=rust:1.96.0-bookworm
ARG PYTHON_VERSION=3.14.6

FROM ${MAVEN_IMAGE} AS maven_toolchain
FROM ${RUST_IMAGE} AS rust_toolchain

FROM python:${PYTHON_VERSION}-slim-bookworm

ARG NODE_VERSION=24.18.0
ARG UV_VERSION=0.11.26
ARG GO_VERSION=1.26.4
ARG PHP_VERSION=8.5.8
ARG RUBY_VERSION=4.0.5
ARG COMPOSER_VERSION=2.10.2
ARG DOTNET_SDK_VERSION=10.0.301
ARG TRIVY_VERSION=0.72.0

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV STREAMLIT_SERVER_HEADLESS=true
ENV STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

ENV JAVA_HOME=/opt/java/openjdk
ENV MAVEN_HOME=/usr/share/maven
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV DOTNET_ROOT=/opt/dotnet
ENV PATH="/opt/node/bin:/opt/php/bin:/opt/ruby/bin:/usr/local/go/bin:/usr/local/cargo/bin:/opt/dotnet:/usr/share/maven/bin:/opt/java/openjdk/bin:${PATH}"

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       autoconf \
       bison \
       build-essential \
       ca-certificates \
       curl \
       git \
       gzip \
       libcurl4-openssl-dev \
       libffi-dev \
       libgdbm-dev \
       libicu72 \
       libncurses-dev \
       libonig-dev \
       libreadline-dev \
       libsqlite3-dev \
       libssl-dev \
       libxml2-dev \
       libyaml-dev \
       libzip-dev \
       make \
       pkg-config \
       re2c \
       tar \
       unzip \
       xz-utils \
       zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=maven_toolchain /opt/java/openjdk /opt/java/openjdk
COPY --from=maven_toolchain /usr/share/maven /usr/share/maven
COPY --from=rust_toolchain /usr/local/rustup /usr/local/rustup
COPY --from=rust_toolchain /usr/local/cargo /usr/local/cargo

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) node_arch="x64"; uv_arch="x86_64-unknown-linux-gnu"; go_arch="amd64"; dotnet_arch="x64"; trivy_arch="64bit" ;; \
      arm64) node_arch="arm64"; uv_arch="aarch64-unknown-linux-gnu"; go_arch="arm64"; dotnet_arch="arm64"; trivy_arch="ARM64" ;; \
      *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    \
    curl -fsSL -o /tmp/node.tar.xz \
      "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${node_arch}.tar.xz"; \
    mkdir -p /opt/node; \
    tar -xJf /tmp/node.tar.xz -C /opt/node --strip-components=1; \
    rm -f /tmp/node.tar.xz; \
    \
    curl -fsSL -o /tmp/uv.tgz \
      "https://releases.astral.sh/github/uv/releases/download/${UV_VERSION}/uv-${uv_arch}.tar.gz"; \
    mkdir -p /tmp/uv-extract; \
    tar -xzf /tmp/uv.tgz -C /tmp/uv-extract; \
    install -m 0755 "/tmp/uv-extract/uv-${uv_arch}/uv" /usr/local/bin/uv; \
    install -m 0755 "/tmp/uv-extract/uv-${uv_arch}/uvx" /usr/local/bin/uvx; \
    rm -rf /tmp/uv.tgz /tmp/uv-extract; \
    \
    curl -fsSL -o /tmp/go.tgz \
      "https://go.dev/dl/go${GO_VERSION}.linux-${go_arch}.tar.gz"; \
    tar -xzf /tmp/go.tgz -C /usr/local; \
    rm -f /tmp/go.tgz; \
    \
    mkdir -p /opt/dotnet; \
    curl -fsSL -o /tmp/dotnet.tar.gz \
      "https://builds.dotnet.microsoft.com/dotnet/Sdk/${DOTNET_SDK_VERSION}/dotnet-sdk-${DOTNET_SDK_VERSION}-linux-${dotnet_arch}.tar.gz"; \
    tar -xzf /tmp/dotnet.tar.gz -C /opt/dotnet; \
    rm -f /tmp/dotnet.tar.gz; \
    \
    curl -fsSL -o /tmp/trivy.tgz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz"; \
    tar -xzf /tmp/trivy.tgz -C /tmp trivy; \
    install -m 0755 /tmp/trivy /usr/local/bin/trivy; \
    rm -f /tmp/trivy /tmp/trivy.tgz

RUN set -eux; \
    curl -fsSL -o /tmp/php.tar.xz \
      "https://www.php.net/distributions/php-${PHP_VERSION}.tar.xz"; \
    mkdir -p /tmp/php-src; \
    tar -xJf /tmp/php.tar.xz -C /tmp/php-src --strip-components=1; \
    cd /tmp/php-src; \
    ./configure \
      --prefix=/opt/php \
      --disable-cgi \
      --enable-cli \
      --enable-mbstring \
      --with-curl \
      --with-openssl \
      --with-pdo-sqlite \
      --with-sqlite3 \
      --with-zip \
      --with-zlib; \
    make -j"$(nproc)"; \
    make install; \
    rm -rf /tmp/php-src /tmp/php.tar.xz; \
    curl -fsSL -o /usr/local/bin/composer \
      "https://getcomposer.org/download/${COMPOSER_VERSION}/composer.phar"; \
    chmod 0755 /usr/local/bin/composer

RUN set -eux; \
    curl -fsSL -o /tmp/ruby.tar.gz \
      "https://cache.ruby-lang.org/pub/ruby/4.0/ruby-${RUBY_VERSION}.tar.gz"; \
    mkdir -p /tmp/ruby-src; \
    tar -xzf /tmp/ruby.tar.gz -C /tmp/ruby-src --strip-components=1; \
    cd /tmp/ruby-src; \
    ./configure --prefix=/opt/ruby --disable-install-doc; \
    make -j"$(nproc)"; \
    make install; \
    rm -rf /tmp/ruby-src /tmp/ruby.tar.gz

COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r /app/requirements.txt \
    && python -m pip check

COPY . /app

EXPOSE 8501

CMD ["streamlit", "run", "streamlit_app.py", "--server.address=0.0.0.0", "--server.port=8501"]
