# Configuration Guide

SecretGuard AI is configured via a `secretguard.toml` file placed in
your project root. All settings are optional — sensible defaults are
applied when no config file is present.

## Quick Start

Create a `secretguard.toml` in your project root:

```toml
[scan]
entropy_threshold = 4.5
extensions = [".py", ".js", ".ts", ".env", ".yaml", ".yml", ".json", ".toml", ".tf"]
```

## Full Reference

### `[scan]` Section

| Key                  | Type       | Default | Description |
|----------------------|------------|---------|-------------|
| `entropy_threshold`  | `float`    | `4.5`   | Shannon entropy threshold (bits per character). Values above this are flagged. |
| `extensions`         | `[string]` | See below | File extensions to scan. |
| `exclude`            | `[string]` | See below | Glob patterns to exclude from scanning. |
| `min_secret_length`  | `int`      | `8`     | Minimum value length to consider. |
| `max_file_size`      | `int`      | `10485760` | Max file size in bytes (default 10 MB). |
| `parallel_workers`   | `int`      | `4`     | Thread pool size for parallel scanning. |
| `extra_placeholders` | `[string]` | `[]`    | Additional placeholder regex patterns. |
| `allowlist_paths`    | `[string]` | `[]`    | Patterns to suppress (same as `.secretguardignore`). |

#### Default Extensions

```toml
extensions = [".py", ".js", ".ts", ".env", ".yaml", ".yml", ".json", ".toml", ".tf"]
```

Files named `Dockerfile` are always scanned regardless of extension.

#### Default Exclude Patterns

```toml
exclude = [
    "node_modules/**", ".git/**", "__pycache__/**", "*.pyc",
    "venv/**", ".venv/**", "dist/**", "build/**",
    "*.egg-info/**", "*.lock", "*.min.js",
]
```

### `[[rules]]` Section — Custom Detection Rules

Add custom regex rules to detect organisation-specific secret formats:

```toml
[[rules]]
id = "internal-token"
pattern = "INTERNAL_TOKEN_[A-Z0-9]{32}"
description = "Internal service authentication token"
severity = "HIGH"

[[rules]]
id = "deploy-key"
pattern = "DEPLOY_KEY_[a-f0-9]{64}"
description = "Deployment key format"
severity = "MEDIUM"
```

Each rule requires:
- `id`: Unique identifier for the rule.
- `pattern`: Python regex pattern (case-insensitive by default).
- `description` (optional): Human-readable description.
- `severity` (optional): `HIGH`, `MEDIUM`, or `LOW` (default: `HIGH`).

## `.secretguardignore` — Allowlist File

Create a `.secretguardignore` file in your project root to suppress
known false positives. One pattern per line:

```text
# File glob patterns
tests/fixtures/*
examples/**

# Variable names (case-insensitive)
EXAMPLE_KEY
DEMO_TOKEN

# SHA-256 fingerprint of a specific value
sha256:e3b0c44298fc1c149afbf4c8996fb924...
```

## Entropy Threshold Guide

| Range      | Typical Content              | Recommendation |
|------------|------------------------------|----------------|
| 0.0 – 2.0 | Repeated chars               | Safe           |
| 2.0 – 3.5 | Simple words, names          | Safe           |
| 3.5 – 4.5 | Mixed prose, variable names  | Usually safe   |
| 4.5 – 5.5 | Base64, hex tokens           | **Suspicious** |
| 5.5 – 6.5+| Cryptographic keys           | **Very likely a secret** |

## CLI Options

### `secretguard check`

```
Options:
  --staged          Scan only staged files (pre-commit mode)
  -t, --threshold   Entropy threshold (default: 4.5)
  --format          Output format: terminal, json, sarif
  -o, --output      Output file path (for json/sarif)
```

### `secretguard scan`

```
Options:
  --history         Walk full git history for lineage tracking
  -t, --threshold   Entropy threshold (default: 4.5)
  --format          Output format: terminal, json, sarif
  -o, --output      Output file path
  -v, --verbose     Show LOW-risk findings
  --no-block        Don't exit with non-zero on HIGH findings
```

### `secretguard init`

Sets up `.gitignore` entries and creates a `.secretguardignore` template.
