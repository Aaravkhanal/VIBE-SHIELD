# Contributing to VIBE SHIELD

Thank you for your interest in contributing to VIBE SHIELD! This document provides guidelines and best practices to make the contribution process smooth for everyone.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Security Vulnerabilities](#security-vulnerabilities)

---

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

---

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/vibe-shield.git
   cd vibe-shield
   ```
3. **Install dependencies**:
   ```bash
   npm install
   npx playwright install chromium
   ```
4. **Create a branch** for your work:
   ```bash
   git checkout -b feature/your-feature-name
   ```

---

## How to Contribute

### Good First Contributions

- Improve documentation or fix typos
- Add test cases for existing modules
- Improve error messages and CLI output
- Add new detection payloads to existing scanners

### Intermediate Contributions

- Add new security detection patterns
- Improve correlation engine rules
- Enhance report output formats
- Performance optimizations

### Advanced Contributions

- New scanner sub-modules
- New agent implementations
- Architecture improvements
- CI/CD pipeline enhancements

---

## Development Setup

### Prerequisites

- **Node.js** ≥ 20
- **npm** ≥ 9
- **Playwright** (Chromium)

### Running a Scan

```bash
# Full scan
node src/cli.js scan https://example.com --verbose

# Specific module
node src/cli.js security https://example.com --verbose

# Limited scope (for testing)
node src/cli.js scan https://example.com --max-pages 3 --max-depth 1
```

### Project Architecture

VIBE SHIELD uses a multi-agent architecture. Before contributing, familiarize yourself with:

- `src/agents/` — Agent system (orchestrator, event bus, base agent)
- `src/core/` — Scanner modules (security, AI, logic, API)
- `src/reporting/` — Report generators (JSON, Markdown, HTML, SARIF)
- `src/utils/` — Shared utilities (config, logging, finding schema)

---

## Code Style

### General Rules

- Use **ES Modules** (`import`/`export`, not `require`)
- Use **async/await** for asynchronous operations
- Use **descriptive variable names** — no single-letter variables except loop indices
- Add **JSDoc comments** for all exported functions and classes
- Keep functions focused — one function, one responsibility
- Maximum line length: **100 characters** (soft limit)

### File Naming

- Use **kebab-case** for filenames: `secret-detector.js`, `auth-flow-tester.js`
- Agent files go in `src/agents/`
- Scanner modules go in `src/core/<category>/`
- Report generators go in `src/reporting/`

### Finding Schema

All findings must use the standard schema from `src/utils/finding.js`:

```javascript
{
  id: 'VIBE SHIELD-<MODULE>-<nanoid>',
  module: 'security' | 'ai' | 'qa' | 'logic' | 'api',
  title: 'Clear, descriptive title',
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info',
  affected_surface: 'https://...',
  description: 'What was found and why it matters',
  reproduction: ['Step 1', 'Step 2', ...],
  evidence: 'Raw evidence string',
  remediation: 'How to fix this'
}
```

---

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

| Type | Usage |
|------|-------|
| `feat` | New feature or scanner |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `perf` | Performance improvement |
| `test` | Adding or updating tests |
| `chore` | Build process, CI, or tooling changes |

### Examples

```
feat(ai): add model fingerprinting detection
fix(security): handle timeout in TLS checker
docs: update CLI reference in README
refactor(agents): extract common retry logic to base agent
```

---

## Pull Request Process

### Before Submitting

1. **Test your changes** by running a scan against a test target
2. **Ensure no regressions** — existing scans should still work
3. **Update documentation** if you changed CLI flags, config options, or behavior
4. **Keep PRs focused** — one feature or fix per PR

### PR Template

When opening a PR, include:

1. **What** — Clear description of the change
2. **Why** — The problem it solves or feature it adds
3. **How** — Technical approach (for non-trivial changes)
4. **Testing** — How you verified the change works

### Review Process

1. All PRs require at least **1 approval** from a maintainer
2. PRs must pass all CI checks
3. Maintainers may request changes — this is normal and constructive
4. Once approved, a maintainer will merge your PR

---

## Reporting Bugs

Use [GitHub Issues](https://github.com/Aaravkhanal/vibe-shield/issues) with the **Bug Report** template.

### Include

- **VIBE SHIELD version** (`vibe-shield --version` or `node src/cli.js --version`)
- **Node.js version** (`node --version`)
- **OS and version**
- **Steps to reproduce** (target URL not required — describe the scenario)
- **Expected behavior** vs **actual behavior**
- **Error output** (with `--verbose` flag)

### Do NOT Include

- Target URLs containing sensitive data
- API keys, tokens, or credentials
- Personally identifiable information

---

## Suggesting Features

Use [GitHub Issues](https://github.com/Aaravkhanal/vibe-shield/issues) with the **Feature Request** template.

Include:
- **Problem statement** — What are you trying to accomplish?
- **Proposed solution** — How would this work?
- **Alternatives considered** — What else did you consider?
- **Additional context** — Screenshots, references, examples

---

## Security Vulnerabilities

> **⚠️ Do NOT open a public issue for security vulnerabilities.**

If you discover a security vulnerability in VIBE SHIELD itself (not in a target being scanned), please report it responsibly:

1. **Email**: aaravkhanal@users.noreply.github.com
2. **Subject**: `[SECURITY] VIBE SHIELD — <brief description>`
3. Include steps to reproduce and potential impact

We will acknowledge receipt within 48 hours and aim to release a fix within 7 days for critical issues.

---

## License

By contributing to VIBE SHIELD, you agree that your contributions will be licensed under the [Vibe Shield Public License v1.0](./LICENSE).

---

Thank you for helping make VIBE SHIELD better! 🔒
