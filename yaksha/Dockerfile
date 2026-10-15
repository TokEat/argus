FROM golang:1.25.4-bookworm AS build
# GOPROXY 默认使用国内镜像保证构建网络可达，可用 --build-arg 覆盖
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}
WORKDIR /src
COPY shared/proto ./shared/proto
WORKDIR /src/yaksha
COPY yaksha/go.mod yaksha/go.sum ./
RUN go mod download
COPY yaksha/cmd ./cmd
COPY yaksha/internal ./internal
RUN GOWORK=off CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/yaksha ./cmd/yaksha

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /tmp \
    && chmod 1777 /tmp
COPY --from=build /out/yaksha /usr/local/bin/yaksha
ENV HOME=/nonexistent \
    YAKSHA_LISTEN_ADDR=127.0.0.1:8790 \
    YAKSHA_WORKERS=2 \
    YAKSHA_QUEUE_SIZE=32 \
    YAKSHA_RECYCLE_AFTER=100
USER 65532:65532
EXPOSE 8790
ENTRYPOINT ["/usr/local/bin/yaksha"]
CMD ["serve"]
