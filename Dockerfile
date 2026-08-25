# ============================================================================
# APIProxy 容器镜像
# 构建：docker build -t apiproxy .
# 运行：docker compose up -d   （推荐，见 docker-compose.yml）
# ============================================================================

# ---------- 构建阶段：安装依赖 ----------
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt


# ---------- 运行阶段：最小镜像 ----------
FROM python:3.12-slim

# 非交互、不写 .pyc
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# tzdata：保证日志/调度器时间按 Asia/Shanghai 显示
RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/*

# 从构建阶段复制依赖（site-packages 与可执行脚本）
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# 非 root 用户 + 数据目录
RUN useradd --create-home --uid 10001 apiproxy \
    && mkdir -p /data /opt/apiproxy \
    && chown -R apiproxy:apiproxy /data /opt/apiproxy

# 复制应用包（保留包名 APIProxy 作为子目录，供 `python -m APIProxy` 定位）
WORKDIR /opt/apiproxy
COPY --chown=apiproxy:apiproxy . /opt/apiproxy/APIProxy/

USER apiproxy

# 数据目录（数据库 / 证书持久化），用 volume 挂载
ENV DB_PATH=/data/users.db \
    TZ=Asia/Shanghai \
    LOG_FORMAT=json

VOLUME ["/data"]

# HTTP 5000 / HTTPS 5443 / RCON 5001
EXPOSE 5000 5443 5001

# 默认 HTTP 启动；设 APIPROXY_SSL_ENABLED=true 时改走 HTTPS（自签名证书自动生成）
CMD ["python", "-m", "APIProxy"]
