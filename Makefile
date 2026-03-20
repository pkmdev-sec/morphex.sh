.PHONY: build install test clean serve generate-key scan download-model lint test-all docker benchmark completion

VERSION := 1.0.0
BINARY := morphex

build:
	cd core && go build -o ../$(BINARY) ./cmd/morphex/

install: build
	install -m 755 $(BINARY) /usr/local/bin/$(BINARY)

test:
	cd engine && go test ./...
	cd core && go test ./...

benchmark: build
	@echo "══════════════════════════════════════════════"
	@echo "  Morphex Reproducible Benchmark Suite"
	@echo "══════════════════════════════════════════════"
	@echo ""
	@bash benchmark/run_benchmark.sh

serve: build
	./$(BINARY) serve --rate-limit 0 --api-keys "$$(./$(BINARY) generate-key --type admin 2>/dev/null | grep Key: | awk '{print $$2}')"

generate-key:
	./$(BINARY) generate-key --set

scan:
	./$(BINARY) scan --json --threshold 0.7 .

scan-deep:
	./$(BINARY) scan --json --deep --threshold 0.5 .

clean:
	rm -f $(BINARY)
	rm -rf .morphex-data/

download-model:
	mkdir -p ml/models
	curl -fSL -o ml/models/model.onnx \
		https://github.com/morphex-security/morphex/releases/download/v$(VERSION)/model.onnx

lint:
	cd engine && golangci-lint run ./...
	cd core && golangci-lint run ./...

test-all: test
	cd api && go test ./...
	cd web && go test ./...

docker:
	docker build -t morphex:latest .

completion:
	@echo "Add to your shell profile:"
	@echo '  eval "$$(morphex completion bash)"   # bash'
	@echo '  eval "$$(morphex completion zsh)"    # zsh'
	@echo '  morphex completion fish | source     # fish'
