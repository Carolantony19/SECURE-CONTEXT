# SECURE-CONTEXT 
# TEAM NAME: GOOFY_CODERS
# TEAM MEMBERS: 
                1. BHARATH P
                2. BHAVANESH L
                3. CAROL ANTONY RANJITH A
# PROBLEM STATEMENT
Current secret-detection tools are pattern-based and reactive — they scan for what a leaked secret looks like, not for the behavioral pattern of how AI-assisted code introduces secrets (e.g., a suspiciously "real" value sitting where an AI-generated placeholder used to be, or copy-pasted example credentials from AI output that were never meant to be replaced). This creates a detection gap specific to AI-assisted development workflows.
# SOLUTION 
     * Detects AI-boilerplate placeholder patterns in code
     * Flags when a placeholder gets replaced with a high-entropy "real-looking" value
     * Scores risk based on file type + entropy, not just regex match
     * Suggests auto-fix (move secret to .env + .gitignore)
# FEATURES 
       1. Regex-based scanner for common secret-assignment patterns across .py, .js, .env, .yaml, .json files.
       2. Shannon entropy scoring to distinguish random-looking real secrets from low-entropy placeholders/words.
       3. Placeholder pattern library (YOUR_*_HERE, <API_KEY>, REPLACE_ME, xxx, example_key, etc.).
       4. Diff-aware placeholder-swap detection: compare a variable's previous committed value against its new staged value; flag if a placeholder was replaced with a high-entropy value.
       5. Composite risk scoring (HIGH / MEDIUM / LOW) combining entropy, file type, and placeholder-swap signal.
       6. Git pre-commit hook that blocks commits on HIGH-risk findings and prints a clear, actionable report.
       7. Remediation guidance: suggest moving secrets to .env and auto-update .gitignore.
       8. Standalone CLI for full-repo audits, independent of git staging.
       9. Colorized, readable terminal output.
       11. Stretch: GitHub Action wrapper for CI enforcement on push/PR.
       12. Stretch: JSON/HTML export of scan results.
# TECH STACK
       - Python 3.11+
       - click (CLI)
       - GitPython (diff/history access) + pre-commit framework (hook lifecycle)
       - rich (terminal output)
       - pytest (testing)
       - pyproject.toml (packaging, pip install -e .)
       - GitHub Actions (stretch CI)
       - Flask + static HTML/JS (stretch dashboard)
# SYSTEM ARCHITECTURE DIAGRAM
                  ┌─────────────────────────────────────────┐
                  │            git commit action            │
                  └────────────────────┬────────────────────┘
                                       │
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │            pre-commit Hook              │
                  │         (Triggers CLI Engine)           │
                  └────────────────────┬────────────────────┘
                                       │
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │             Diff Extractor              │
                  │   (Parses added/modified lines & AST)   │
                  └────────────────────┬────────────────────┘
                                       │
                                 ┌─────┴─────┐
                                 │           │
                                 ▼           ▼
                   ┌──────────────────┐ ┌──────────────────┐
                   │ Staged Added     │ │ Staged Deleted/  │
                   │ Lines            │ │ Git History      │
                   └────────┬─────────┘ └────────┬─────────┘
                            │                    │
                            └──────────┬─────────┴────────┐
                                       │                  │
                                       ▼                  ▼
          ┌────────────────────────────────────────┐ ┌───────────────────────────────┐
          │           Analysis Pipeline            │ │    State Engine (Context)     │
          │ 1. Known Regex Pattern Matcher        │ │ 1. Historical Placeholder     │
          │ 2. Shannon Entropy Calculator          │ │    Substitution Tracker       │
          │ 3. AI-Boilerplate Context Parser       │ │ 2. File Scoping & Environment │
          │ 4. Comment/Docstring Proximity Inspector│ │    Path Heuristics            │
          └───────────────────┬────────────────────┘ └──────────────┬────────────────┘
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       │
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │            Risk Scoring Model           │
                  │     S = w1(Pattern) + w2(Entropy) +     │
                  │       w3(Context) + w4(History)         │
                  └────────────────────┬────────────────────┘
                                       │
                          ┌────────────┴────────────┐
             Score >= Threshold?                    Score < Threshold?
                          │                                 │
                          ▼                                 ▼
         ┌─────────────────────────────────┐       ┌─────────────────┐
         │       BLOCK COMMIT & REPORT     │       │   ALLOW COMMIT  │
         │ - Terminal warning display      │       └─────────────────┘
         │ - Suggest env var substitution  │
         │ - Auto-fix prompt (.env insert) │
         └─────────────────────────────────┘
# WORKFLOW
# FOLDER STRUCTURE
          secretguard-ai/

          ├── secretguard/

          │   ├── __init__.py

          │   ├── cli.py

          │   ├── scanner.py

          │   ├── entropy.py

          │   ├── placeholders.py

          │   ├── diff_analyzer.py
   
          │   ├── risk_scorer.py

          │   ├── report.py

          │   └── config.py

          ├── hooks/

          │   └── pre_commit_hook.py

          ├── .github/workflows/secretguard-ci.yml

          ├── tests/

          │   ├── test_entropy.py

          │   ├── test_scanner.py
    
          │   ├── test_placeholders.py

          │   └── fixtures/

          │       ├── clean_file.py

          │       └── leaky_file.py

          ├── examples/demo_repo/

          ├── .pre-commit-config.yaml

          ├── .gitignore

          ├── pyproject.toml

          ├── README.md

          └── LICENSE
# SECURITY MEASURES
        1. Strict Value Masking: Raw secret values detected in scanned files are masked in terminal reports, log outputs, JSON, and HTML exports (showing only the first 6 characters followed by asterisks) to prevent secondary credential leaks in build logs or console output.
       2.  Zero Ingest / Local-Only Processing: Scanner logic, diff analysis, and Shannon entropy calculations execute entirely client-side. No source code, diffs, or detected candidate strings are transmitted over external networks or third-party APIs.
       3.  Synthetic Test Data Enforcement: All unit tests, fixtures, and demo repository files strictly enforce the use of synthetic credential strings (e.g., sk-fake000..., ghp_fakeToken...) to prevent accidental leaks of real developer keys.
       4. Hook Defense in Depth: Pre-commit hooks operate with failure-safe fallbacks: if hook infrastructure fails, non-blocking logs are printed without silently swallowing staged code, while HIGH-risk security findings strictly block git execution via non-zero exit codes (exit 1).
       5. Least-Privilege Git Access: Git access via GitPython is strictly read-only on the local tree and staging index. The tool never mutates git commits or history autonomously.
# TESTING AND PERFORMANCE
      Testing Metrics
           - Unit Test Suite: 67 automated test cases covering core modules (entropy.py, scanner.py, placeholders.py).
           - Pass Rate: 100% pass rate (67 passed in 0.25s).
           - Fixture Matrix: Tested against clean files (clean_file.py), multi-language secret assignments (.py, .js, .env, .yaml, .json), and synthetic leak scenarios (leaky_file.py).
      Performance Benchmarks
          - Execution Speed: Sub-millisecond parsing per file (~0.25 seconds total for full test suite execution).
          - Pre-commit Latency: Staged-file scanning adds negligible delay (< 50ms for typical developer commits), keeping git workflow fast and frictionless.
          - Memory Footprint: Low overhead (< 30 MB peak RAM usage), operating streaming line-by-line regex scanning on staged blobs without loading full git objects into memory.
# CHALLENGES FACED
        - Differentiating High-Entropy Prose vs. Real Secrets: Distinguishing complex variable names or base64 asset paths from true API tokens required combining Shannon entropy with character-set diversity scoring (charset_bonus) and file-type risk weighting.
        - Detecting AI Placeholder Swaps Across Commits: Static regex scanners only evaluate snapshot files. Building GitPython diff tracking (diff_analyzer.py) to map historical committed variables (YOUR_API_KEY_HERE) against staged replacements required handling new file creation, initial commits, and missing HEAD states cleanly.
        - Minimizing False Positives: Broad regular expressions risk flagging standard English strings or test identifiers. Implementing a multi-stage classification pipeline (Regex $\rightarrow$ Length cutoff $\rightarrow$ Entropy score $\rightarrow$ Placeholder library filter) eliminated false positive noise.
# FUTURE SCOPE
        - AST-Based Semantic Parsing: Extend beyond regex to Abstract Syntax Tree (AST) parsing for Python (ast) and JavaScript/TypeScript (via Tree-sitter) to track secret flow through variable reassignments.
        - Custom AI Classifier: Train a lightweight local ONNX transformer classifier to detect secret context beyond entropy and static patterns.
        - Automated Remediation (secretguard fix): Provide automated CLI refactoring commands to extract staged secrets into local .env files and update source code imports.
        - IDE Extensions: Build a VS Code / JetBrains extension for real-time squiggly line warnings as developers paste or write AI-generated credentials
# DEMO
<img width="927" height="660" alt="image" src="https://github.com/user-attachments/assets/2cfdef62-49a6-41c4-8206-3a9d18634924" />

# REFERENCE
        - Shannon, C. E. (1948). A Mathematical Theory of Communication. Bell System Technical Journal, 27(3), 379–423.
        - GitLeaks — Audit git repositories for secrets: github.com/gitleaks/gitleaks
        - TruffleHog — Find credentials hidden in your commits: github.com/trufflesecurity/trufflehog
        - Git Pre-commit Hook Documentation: git-scm.com/docs/githooks
        - OWASP Top 10 — A07:2021 Identification and Authentication Failures: owasp.org
