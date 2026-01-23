.PHONY: all clean generate deps

PROTO_DIR := proto
GEN_DIR := gen/go
PROTO_FILES := $(shell find $(PROTO_DIR) -name '*.proto')

# Tool versions
PROTOC_GEN_GO_VERSION := v1.32.0
PROTOC_GEN_GO_GRPC_VERSION := v1.3.0

all: generate

deps:
	@echo "Installing protoc plugins..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)

generate: deps
	@echo "Generating Go code from proto files..."
	@mkdir -p $(GEN_DIR)/powermanage/v1
	protoc \
		--proto_path=$(PROTO_DIR) \
		--go_out=$(GEN_DIR) \
		--go_opt=paths=source_relative \
		--go-grpc_out=$(GEN_DIR) \
		--go-grpc_opt=paths=source_relative \
		$(PROTO_FILES)
	@echo "Generation complete."

clean:
	@echo "Cleaning generated files..."
	rm -rf $(GEN_DIR)

# Verify generated code compiles
verify: generate
	cd $(GEN_DIR) && go build ./...
