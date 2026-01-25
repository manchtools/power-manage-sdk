.PHONY: all clean generate deps deps-ts generate-go generate-ts verify inject-tags

PROTO_DIR := proto
GEN_DIR_GO := gen/go
GEN_DIR_TS := gen/ts
PROTO_FILES := $(shell find $(PROTO_DIR) -name '*.proto')

# Tool versions
PROTOC_GEN_GO_VERSION := v1.32.0
PROTOC_GEN_GO_GRPC_VERSION := v1.3.0
PROTOC_GEN_CONNECT_GO_VERSION := v1.16.0

all: generate

deps:
	@echo "Installing Go protoc plugins..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)
	go install connectrpc.com/connect/cmd/protoc-gen-connect-go@$(PROTOC_GEN_CONNECT_GO_VERSION)
	go install github.com/favadi/protoc-go-inject-tag@latest

deps-ts:
	@echo "Installing TypeScript protoc plugins..."
	@if ! command -v npm &> /dev/null; then \
		echo "npm not found, skipping TypeScript deps"; \
	else \
		npm install; \
	fi

generate: generate-go inject-tags generate-ts

generate-go: deps
	@echo "Generating Go code from proto files..."
	@mkdir -p $(GEN_DIR_GO)/powermanage/v1
	protoc \
		--proto_path=$(PROTO_DIR) \
		--go_out=$(GEN_DIR_GO) \
		--go_opt=paths=source_relative \
		--go-grpc_out=$(GEN_DIR_GO) \
		--go-grpc_opt=paths=source_relative \
		--connect-go_out=$(GEN_DIR_GO) \
		--connect-go_opt=paths=source_relative \
		$(PROTO_FILES)
	@echo "Go generation complete."

# Inject validation tags using protoc-go-inject-tag
inject-tags:
	@echo "Injecting validation tags into generated Go code..."
	@find $(GEN_DIR_GO) -name "*.pb.go" -exec protoc-go-inject-tag -input={} \;
	@echo "Validation tags injected."

generate-ts: deps-ts
	@echo "Generating TypeScript code from proto files..."
	@if ! command -v npm &> /dev/null; then \
		echo "npm not found, skipping TypeScript generation"; \
	else \
		mkdir -p $(GEN_DIR_TS); \
		protoc \
			--proto_path=$(PROTO_DIR) \
			--plugin=protoc-gen-es=./node_modules/.bin/protoc-gen-es \
			--plugin=protoc-gen-connect-es=./node_modules/.bin/protoc-gen-connect-es \
			--es_out=$(GEN_DIR_TS) \
			--es_opt=target=ts \
			--connect-es_out=$(GEN_DIR_TS) \
			--connect-es_opt=target=ts \
			$(PROTO_FILES); \
		echo "TypeScript generation complete."; \
	fi

clean:
	@echo "Cleaning generated files..."
	rm -rf $(GEN_DIR_GO) $(GEN_DIR_TS)

# Verify generated code compiles
verify: generate
	cd $(GEN_DIR_GO) && go build ./...
