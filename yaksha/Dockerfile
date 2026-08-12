FROM golang:1.25.4-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN GOWORK=off CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/yaksha ./cmd/yaksha

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /tmp \
    && chmod 1777 /tmp
COPY --from=build /out/yaksha /usr/local/bin/yaksha
ENV HOME=/nonexistent \
    YAKSHA_LISTEN_ADDR=:8790 \
    YAKSHA_WORKERS=2 \
    YAKSHA_QUEUE_SIZE=32 \
    YAKSHA_RECYCLE_AFTER=100
USER 65532:65532
EXPOSE 8790
ENTRYPOINT ["/usr/local/bin/yaksha"]
CMD ["serve"]
