# Multi-target build for the VIndex SumDB Docker Compose stack (sumdbproxy + vindexd)
FROM golang:1.27.4-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY sumdb/ ./sumdb/
COPY vindex/ ./vindex/

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -buildvcs=false -ldflags="-s -w" -o /bin/sumdbproxy ./sumdb/cmd
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -buildvcs=false -ldflags="-s -w" -o /bin/vindexd ./vindex/cmd/vindexd
RUN GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-buildid=" -buildmode=c-shared \
    -o /bin/sumdb.wasm ./vindex/mapfn/examples/sumdb

# Target 1: sumdbproxy runtime image
FROM alpine:3.21 AS sumdbproxy

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 65532 -S vindex \
    && adduser -u 65532 -S -G vindex vindex

COPY --from=builder /bin/sumdbproxy /usr/local/bin/sumdbproxy

USER 65532:65532
EXPOSE 8089

ENTRYPOINT ["/usr/local/bin/sumdbproxy"]
CMD ["--listen=:8089"]

# Target 2: vindexd runtime image with bundled sumdb.wasm
FROM alpine:3.21 AS vindexd

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 65532 -S vindex \
    && adduser -u 65532 -S -G vindex -h /data vindex \
    && mkdir -p /data/db /data/mpt /data/outputlog /data/tiles /etc/vindex \
    && chown -R 65532:65532 /data

COPY --from=builder /bin/vindexd /usr/local/bin/vindexd
COPY --from=builder /bin/sumdb.wasm /etc/vindex/mapfn.wasm

USER 65532:65532
WORKDIR /data
EXPOSE 8080 9090

ENTRYPOINT [ \
  "/usr/local/bin/vindexd", \
  "--wasm_path=/etc/vindex/mapfn.wasm", \
  "--input_log_url=http://sumdbproxy:8089", \
  "--input_log_origin=go.sum database tree", \
  "--input_log_pubkey=sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8", \
  "--output_log_signer_key=PRIVATE+KEY+sumdb.vindex.local+9a36b0c7+ARiBJ2/3cKubDDLD8syZV4N9Du4kXvy/nWRCEzUYYvw6", \
  "--db_path=/data/db", \
  "--mpt_dir=/data/mpt", \
  "--output_log_dir=/data/outputlog", \
  "--tile_cache_dir=/data/tiles", \
  "--listen_addr=:8080", \
  "--metrics_addr=:9090", \
  "--enable_ui=true" \
]
CMD []
