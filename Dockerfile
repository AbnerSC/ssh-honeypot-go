# =====================================================================
# ssh-honeypot-j（Go 版）多架构镜像构建文件（linux/amd64 & linux/arm64）
#
# 多阶段构建：
#   - 编译阶段固定在构建机原生架构（--platform=$BUILDPLATFORM），通过
#     GOOS/GOARCH 交叉编译出目标架构静态二进制（CGO_ENABLED=0），编译阶段无需 QEMU
#   - 运行阶段基于 debian bookworm-slim（官方多架构镜像），安装 curl（兼容存量
#     compose 的 healthcheck）与 tzdata（TZ=Asia/Shanghai 下本地时间与 Java 版一致），
#     该阶段的 apt-get 以目标架构执行，跨架构构建需要 QEMU（CI 已通过 setup-qemu 提供）
#
# 与 Java 版镜像的兼容性：
#   - 镜像名保持 ssh-honeypot-j；工作目录 /app、config.yaml、logs/、db/ 路径不变
#   - 端口 2222/2323/3306/5432/6379/8080 与 Java 版一致
#   - hostkey 存 /app/db/hostkey.ser，随 /app/db 卷持久化，指纹不随重建漂移
#   - 非 root 运行：镜像 USER 10001:10001 仅作兜底，实际身份由 compose 的 user: 决定
#
# 本地手动构建多架构镜像：
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -t ssh-honeypot-j:latest --push .
# 国内环境构建可注入模块代理与 apt 镜像源：
#   --build-arg GOPROXY=https://repo.pi.mmxx.fun/repository/go-public,direct
#   --build-arg APT_MIRROR=repo.huaweicloud.com
# =====================================================================

# 全局 ARG：构建与运行基础镜像都必须在第一个 FROM 之前声明，否则后续 FROM 无法引用
ARG GO_IMAGE=golang:1.27-bookworm
ARG BASE_IMAGE=debian:bookworm-slim
ARG APT_MIRROR=

# ---------- 阶段一：编译 ----------
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
WORKDIR /build

# 可选：模块代理默认不注入，保持 Go 官方默认行为，供 GitHub Actions / 本地直接构建；
# 国内环境由 Gitea Actions 通过 build-arg 注入内部 Go 代理
ARG GOPROXY
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
ENV CGO_ENABLED=0
# 仅在显式传入时才写入 go env（持久化到后续构建步骤），未传时完全不改动默认代理
RUN if [ -n "$GOPROXY" ]; then go env -w GOPROXY="$GOPROXY"; fi

# 先拷依赖清单预取模块，源码变更时可复用 Docker 层缓存
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# TARGETOS/TARGETARCH 由 buildkit 按 --platform 自动注入
ARG TARGETOS
ARG TARGETARCH
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
        -trimpath -buildvcs=false \
        -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildAt=${BUILD_DATE}" \
        -o /out/honeypot ./cmd/honeypot

# ---------- 阶段二：运行时镜像 ----------
FROM ${BASE_IMAGE}
WORKDIR /app

ARG APT_MIRROR
# curl 为兼容存量 compose 的 healthcheck（curl -f http://127.0.0.1:8080）；
# tzdata 保证 TZ=Asia/Shanghai 下的本地时间与 Java 版一致
RUN if [ -n "${APT_MIRROR}" ]; then \
        sed -i "s|deb.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list.d/debian.sources 2>/dev/null || true; \
        sed -i "s|security.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list.d/debian.sources 2>/dev/null || true; \
        sed -i "s|deb.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list 2>/dev/null || true; \
    fi && \
    apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl tzdata passwd && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /out/honeypot /app/honeypot
COPY config.yaml /app/config.yaml
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# 默认非 root 账号（仅作 docker run 时的兜底）：实际执行身份由 compose 的 user: 决定，
# 因此 /app 内文件需对任意 UID 可读可执行，logs/db 预留可写权限（实际以挂载卷权限为准）
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh && \
    chmod +x /usr/local/bin/docker-entrypoint.sh && \
    groupadd -g 10001 honeypot && \
    useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin honeypot && \
    mkdir -p /app/logs /app/db && \
    chown -R 10001:10001 /app && \
    chmod 0755 /app /app/honeypot && \
    chmod 0644 /app/config.yaml && \
    chmod 0777 /app/logs /app/db

# 兜底声明：compose 未写 user: 时也不会以 root 运行；
# compose 中 user: "<UID>:<GID>" 可覆盖此默认值
USER 10001:10001
ENV HOME=/tmp

ENTRYPOINT ["docker-entrypoint.sh"]

# 存活探测：内置子命令探测本地监听端口（Web 优先，其次 SSH 等），
# 配合 restart 策略兜住进程异常退出/端口未就绪
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/app/honeypot", "-health"]

EXPOSE 2222 2323 3306 5432 6379 8080
VOLUME ["/app/logs", "/app/db"]
