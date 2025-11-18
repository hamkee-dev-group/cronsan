# cronsan — A Pure-C Lightweight Crontab Linter & Sanitizer

cronsan is a pure C, dependency-free, security-focused crontab linter, sanitizer, and schedule analyzer designed for reliability in sensitive and high-stakes environments.
It aims to be a modern, safe, auditable alternative to ad-hoc cron parsing tools and shell scripts.

Cron is simple, but cron syntax isn’t. Misconfigured jobs can silently break systems, overload CPUs, or trigger dangerous operational cascades. cronsan addresses this by performing real parsing, real validation, and real schedule reasoning — all in a single, small, portable C program.

## 🚀 Features

### ✓ Fully compliant cron parser
- Supports standard 5-field cron expressions
- Handles lists, ranges, steps (`*/5`, `1-10/2`, `1,3,7`)
- Accepts month and weekday names (`JAN`, `MON`)
- Supports standard @special schedules:
  - `@reboot`
  - `@hourly`
  - `@daily` / `@midnight`
  - `@weekly`
  - `@monthly`
  - `@yearly` / `@annually`

### ✓ Strict validation
- Detects invalid ranges, malformed steps, illegal tokens, and out-of-range values
- Validates DOM/DOW logic (Vixie cron semantics)
- Flags malformed environment lines
- Warns for suspicious patterns (e.g., every-minute jobs)

### ✓ Next-run reasoning
- Computes the next scheduled run for each job
- Configurable horizon (default: 24 hours)
- Uses UTC for deterministic behavior

### ✓ Overlap detection
Finds cron jobs scheduled to run at the exact same minute within a given window.

### ✓ Enterprise-grade focus
- Pure C11, no dependencies
- Auditable control flow
- Limited and safe memory allocations
- Suitable for static-analysis, fuzzing, and hardening
- Works on Linux, BSDs, macOS, and minimal embedded POSIX systems

## 📦 Building

Requires any C11 compatible compiler.

```
make
```

## 🧪 Usage

### Read from a file:

```
./cronsan -f /etc/crontab
```

### Read from stdin:

```
crontab -l | ./cronsan
```

### Increase the overlap-detection window:

```
./cronsan -f /etc/crontab -H 48
```

## 📄 Example Output

```
Parsed 5 jobs.

Job at line 3: /usr/local/bin/backup
  Next run within 24 hours: 2025-03-22 00:00 UTC

Job at line 7: /usr/local/bin/cache-rotate
  WARNING: runs every minute. Ensure this is intentional.
  Next run within 24 hours: 2025-03-21 15:05 UTC

WARNING: jobs on lines 3 and 7 overlap at 2025-03-22 00:00 UTC
```

## 🛡️ Safety Philosophy

cronsan was designed with a conservative engineering mindset:

- No dynamic memory proportional to input size
- No recursion
- No unsafe library calls
- Deterministic behavior suitable for production pipelines
- Small, inspectable codebase
- Minimal attack surface

## 🧩 Project Structure

```
.
├── cronsan.c
├── Makefile
└── README.md
```

## 📚 Roadmap

- Optional JSON output
- Dangerous-pattern detectors
- Library version (libcronsan)
- Fuzzing harness
- Strict POSIX mode

## 🤝 Contributing

Contributions and suggestions are welcome.

## 📝 License

MIT License.
