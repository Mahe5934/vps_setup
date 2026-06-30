# Project-Specific Lessons Learned

## 2026-06-30: VPS Setup Script Rewrites

- **Project Name:** VPS Setup Script Rewrites
- **Tech Stack:** Python, Bash, Debian/Ubuntu System Administration
- **Issue/Correction:** Bash script syntax errors due to invoking functions with Python-like parentheses (e.g. `log_info("...")` and `check_root()`).
- **Root Cause:** Mixing syntax styles while writing equivalent Python and Bash scripts in parallel.
- **Prevention Rule:** In Bash, function invocations must use space-separated arguments without parentheses. Always verify shell syntax with `bash -n` or dry-run checks.
- **Example:**
  - *Incorrect:* `log_info("Created user")` or `check_root()`
  - *Correct:* `log_info "Created user"` or `check_root`
