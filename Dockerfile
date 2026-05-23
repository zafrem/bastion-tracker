FROM golang:1.21-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/tracker-cli ./cmd/tracker-cli

FROM alpine:3.19
RUN apk add --no-cache ca-certificates curl
COPY --from=builder /bin/tracker-cli /usr/local/bin/tracker-cli
EXPOSE 8080 9090 9091
ENTRYPOINT ["tracker-cli"]
CMD ["server"]
