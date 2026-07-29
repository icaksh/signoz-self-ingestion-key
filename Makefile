.PHONY: build run test clean

build:
	CGO_ENABLED=0 go build -o bin/proxy ./cmd/proxy

run:
	go run ./cmd/proxy

test:
	go test ./...

clean:
	rm -rf bin/ *.db
