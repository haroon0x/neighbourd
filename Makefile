BINARY := veranda
VERSION := 0.1.0

.PHONY: build test vet fmt check clean

build:
	go build -trimpath -ldflags "-s -w" -o $(BINARY) ./cmd/veranda

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

check: vet test
	gofmt -l . | tee /dev/stderr | grep -q . && exit 1 || true

clean:
	rm -f $(BINARY)
