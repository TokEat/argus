FROM golang:1.25-alpine AS build
WORKDIR /src
COPY exp-lab/canary/main.go ./main.go
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/argus-exp-canary ./main.go

FROM scratch
COPY --from=build /out/argus-exp-canary /argus-exp-canary
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/argus-exp-canary"]
