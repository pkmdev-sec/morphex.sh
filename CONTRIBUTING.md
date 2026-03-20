# Contributing to MORPHEX

Thanks for wanting to help. Here's how to get started.

## What You Can Contribute

**Good first issues:**
- Add a new known credential prefix to the Aho-Corasick trie
- Add a placeholder string to the dead-values database
- Add a test case for an obfuscation pattern
- Improve file provenance classification for a new file type

**Medium effort:**
- Add a new fast-path HTTP verifier for a service
- Add a new FP signal for a false-positive pattern you've seen
- Improve ML training data with labeled examples

**Large effort:**
- New advanced extraction transform (obfuscation defeat)
- New output format
- Performance optimization with benchmarks

## Development Setup

```bash
git clone https://github.com/morphex-security/morphex.git
cd morphex

# Build
make build

# Run all tests
make test-all

# Lint
make lint
```

Requires Go 1.22+ and optionally golangci-lint.

## Making Changes

1. Fork the repo and create a branch from `main`
2. Write your code
3. Add tests — if you're adding a detector, prefix, or signal, add test cases
4. Run `make test-all` and `make lint`
5. Open a PR with a clear description of what you changed and why

## Code Style

- Follow existing patterns in the file you're editing
- No magic numbers — use named constants
- Tests go next to the code they test (`_test.go`)
- Signal-based detection only — we don't add regex pattern detectors

## The Rule

MORPHEX is signal-based, not pattern-based. We don't accept PRs that add regex-based secret detection rules. If you want to improve detection, contribute to the signal pipeline, the FP elimination signals, or the verification fast-paths.

This is a philosophical choice, not a technical limitation. Regex detectors are what every other scanner does. We do something different.

## Reporting Security Issues

See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 license.
