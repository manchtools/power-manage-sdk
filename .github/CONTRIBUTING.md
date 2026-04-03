# Contributing to Power Manage SDK

## Prerequisites

- Go 1.25+
- [Buf](https://buf.build/) and `protoc` for protobuf generation
- `make` for running generators

## Getting Started

This repo is part of a Go workspace. Clone all four repos (`sdk`, `server`, `agent`, `web`) into the same parent directory.

```bash
# Regenerate protobuf code (after editing proto/pm/v1/*.proto)
make generate

# Run tests
go test ./...
```

Proto definitions are in `proto/pm/v1/`. Generated Go code lives in `gen/`. Go library packages are in `go/`. See `CLAUDE.md` for the full build command reference.

## Workflow

1. Create a branch from `main`.
2. Make your changes with conventional commit messages:
   - `feat:` new feature
   - `fix:` bug fix
   - `chore:` maintenance
   - `docs:` documentation
   - `refactor:` code restructuring
   - `perf:` performance improvement
   - `test:` test additions/changes
3. Open a pull request. CodeRabbit reviews automatically.
4. Ensure CI passes before requesting review.

## Code Style

- Follow existing patterns in the codebase.
- Always handle errors -- never silently ignore them.
- Proto files follow the Buf style guide.

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 license.
