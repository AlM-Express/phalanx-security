# Phalanx

**Phalanx** is a Go-based security CLI for Node.js projects that helps reduce supply-chain risk during dependency installation. It scans packages, inspects lifecycle scripts, records suspicious behavior, and verifies dependency integrity with a lock-style baseline.

## What it does

Phalanx is designed to sit in front of normal Node.js dependency workflows and add security checks before and during package installation.

It currently supports:

- A safer install flow that fetches dependencies without running npm lifecycle scripts directly
- Static analysis of dependencies and package metadata for suspicious patterns
- Runtime monitoring of lifecycle script execution through Phalanx-controlled execution
- Behavior-based findings from monitored commands and script activity
- Trust locking and verification of the installed dependency tree
- Human-readable console output and JSON output for automation

## Why Phalanx exists

Node.js supply-chain attacks often hide inside packages that look normal at first glance. Malicious packages may use install scripts, run shell commands, reach out to remote servers, or modify local files during installation.

Phalanx helps detect and reduce that risk by adding security checks around the installation process instead of blindly trusting packages.

## Features

### Secure install flow
Phalanx installs dependencies in a safer way by preventing npm lifecycle scripts from running automatically during the install step.

### Static package scanning
Phalanx scans dependency files and package manifests for suspicious indicators such as:

- Shell execution
- Dynamic code evaluation
- Network activity
- File system tampering
- Obfuscation or anti-analysis behavior

### Runtime monitoring
Lifecycle scripts are executed through Phalanx’s own control layer so suspicious activity can be observed and scored.

### Trust lock and verification
Phalanx can record a baseline of the installed dependency tree and later verify whether files have changed.

### Reporting
Results can be shown in a readable terminal report and also exported as JSON for tooling and automation.

## Installation

Build from source:

```bash
# clone the repository
git clone https://github.com/AlM-Express/phalanx-security.git
cd phalanx-security

# build the CLI
go build -o phalanx ./cmd/phalanx
```

Or install from a release binary if you publish one.

## Usage

### Secure install

```bash
phalanx install
```

This runs the safer install flow, scans dependencies, and evaluates risk before allowing the installation result to settle.

### Audit a project

```bash
phalanx audit
```

Runs a scan over the project and reports suspicious findings.

### Create a trust baseline

```bash
phalanx trust-lock
```

Creates a baseline hash record for the installed dependency tree.

### Verify the current tree

```bash
phalanx verify
```

Checks the current dependency tree against the saved baseline.

## Output modes

Phalanx supports readable terminal output and JSON output for automation-friendly pipelines.

Example:

```bash
phalanx audit --json
```

## How it works

Phalanx uses three layers:

1. **Static scanning** — inspects dependency files and package metadata for suspicious patterns
2. **Controlled execution** — lifecycle scripts are run through Phalanx rather than being left completely to npm
3. **Behavior scoring** — observed script activity is converted into findings that affect the final risk score

## Project structure

Typical structure:

- `cmd/phalanx/` — CLI entry points and commands
- `internal/scan/` — static scanning and findings collection
- `internal/lifecycle/` — lifecycle script discovery and controlled execution
- `internal/manager/` — npm interaction helpers
- `internal/verify/` — trust lock and integrity verification
- `internal/report/` — report formatting and output

## Limitations

Phalanx is a strong security layer for Node.js installs, but it is not a full operating-system sandbox.

It currently focuses on:

- Safer install behavior
- Script monitoring
- Static and behavioral risk scoring
- Integrity verification

For production environments that need stronger containment, Phalanx can be paired with OS-level sandboxing, container isolation, or CI policy enforcement.

## Acknowledgments

Built to help developers reduce Node.js supply-chain risk and make dependency installs safer by default.

