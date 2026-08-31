.PHONY: build run test test-race vet fmt clean check

build:
	CGO_ENABLED=0 go build -o bin/proxy ./cmd/proxy

run:
	go run ./cmd/proxy

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(find . -type f -name '*.go' -not -path './.git/*' -not -path './.pi/*' -not -path './.reference/*')

check:
	bash scripts/verify-rewrite.sh

clean:
	rm -rf bin/ *.db

.PHONY: install-tui
install-tui:
	./install.sh
