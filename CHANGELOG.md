# Changelog

## [1.0.0] — 2026-03-12

### Added
- **Token Tracker**: Per-call token logging with persistent JSONL storage
- **Cost Calculator**: Multi-model pricing with caching (90% discount) and batch (50% discount) support
- **Model Router**: Intelligent model selection based on task complexity, budget, and quality requirements
- **Budget Enforcer**: Session/project/team spending limits with alerts and blocking
- **Cache Maximizer**: Prompt analysis, restructuring for cache hits, and savings projection
- **Attribution Engine**: Cost tagging by project, team, and feature with invoice generation
- **Hooks**: PostToolUse tracker and PreToolUse budget gate (Python)
- **Tests**: 156 tests across 6 test suites with 100% pass rate
