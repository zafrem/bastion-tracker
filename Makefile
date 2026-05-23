.PHONY: all build test lint clean docker run demo stream

BINARY := tracker-cli
CMD     := ./cmd/tracker-cli

all: build

build:
	go build -ldflags="-s -w" -o bin/$(BINARY) $(CMD)

test:
	go test ./... -race -timeout 60s

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/

docker:
	docker build -t bastion/tracker:dev .

run:
	go run $(CMD) server

demo:
	go run $(CMD) demo-server

stream:
	go run $(CMD) stream --tail

generate:
	go run $(CMD) generate --rate 5 --duration 60s

tidy:
	go mod tidy

.DEFAULT_GOAL := build
