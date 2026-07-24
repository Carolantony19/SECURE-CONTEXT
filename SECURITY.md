# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in SecretGuard AI itself
(e.g., a regex bypass that causes real secrets to be missed, or a
bug that leaks detected values), please report it responsibly.

### How to Report

1. **Do NOT open a public GitHub Issue** for security vulnerabilities.
2. Send an email to the project maintainers describing:
   - The vulnerability and its impact.
   - Steps to reproduce.
   - Affected versions.
3. You will receive an acknowledgment within 48 hours.

### What Constitutes a Security Issue

- **Scanner bypass**: A pattern that causes a real secret to be
  classified as LOW or SUPPRESSED when it should be HIGH.
- **Value leakage**: A bug that causes raw (unmasked) secret values
  to appear in log output, report files, or error messages.
- **Allowlist bypass**: A way to craft `.secretguardignore` patterns
  that inadvertently suppress legitimate findings.
- **Dependency vulnerability**: A known CVE in a runtime dependency
  (GitPython, Click, Rich, etc.).

### What Is NOT a Security Issue

- False positives (flagging a non-secret as HIGH) — these are bugs,
  not security issues. Please open a regular GitHub Issue.
- Feature requests for new file types or patterns.

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.x     | ✅ Active support  |
| < 1.0   | ❌ No support      |

## Security Best Practices for Users

1. **Always run `secretguard scan .` before pushing** to catch
   any secrets that pre-commit hooks may have missed.
2. **Use `--history` mode periodically** to audit your repo's
   full commit history for past placeholder swaps.
3. **Keep `.env` in `.gitignore`** — never commit environment files.
4. **Rotate any secret that was ever committed**, even if you
   removed it in a later commit. Git history is permanent.
