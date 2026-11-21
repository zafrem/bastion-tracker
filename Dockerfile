FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /bin/tracker-cli ./cmd/tracker-cli

FROM alpine:3.22
RUN apk add --no-cache ca-certificates curl \
    && addgroup -S -g 10001 app && adduser -S -u 10001 -G app app
COPY --from=builder /bin/tracker-cli /usr/local/bin/tracker-cli
USER app
EXPOSE 8080 9090 9091
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s \
  CMD curl -sf http://localhost:8080/v1/health/live || exit 1
ENTRYPOINT ["tracker-cli"]
CMD ["server"]
