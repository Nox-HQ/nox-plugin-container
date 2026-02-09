# nox-plugin-container

**Scan Dockerfiles for security misconfigurations, dangerous patterns, and best practice violations.**

<!-- badges -->
![Track: Core Analysis](https://img.shields.io/badge/track-Core%20Analysis-darkblue)
![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)
![Go 1.25+](https://img.shields.io/badge/go-1.25%2B-00ADD8)

---

## Overview

`nox-plugin-container` performs comprehensive security linting of Dockerfiles, detecting 12 categories of misconfigurations ranging from critical remote code execution risks to low-severity best practice violations. It catches containers running as root, untagged or `:latest` base images, sensitive files copied into images, secrets hardcoded in ENV instructions, remote scripts piped to shell, excessive file permissions, and missing health checks.

Container images are the deployment unit for most modern applications, and Dockerfiles define their security posture. A container running as root (the default) means any exploited vulnerability grants full container access. An untagged base image means your build is not reproducible and may pull in vulnerable versions silently. A `curl | sh` pattern in a RUN instruction executes arbitrary code from the internet during build time. These are not theoretical risks -- they are the most common container security findings in production environments.

The plugin resolves line continuations (backslash at end of line) before analysis, ensuring that multi-line RUN instructions are evaluated as complete commands. It identifies Dockerfiles by name patterns (`Dockerfile`, `Dockerfile.*`, `*.dockerfile`) and applies all 12 rules to each discovered file. Each finding includes the relevant CWE identifier for integration with vulnerability management systems.

## Use Cases

### CI/CD Pipeline Gate

Integrate this plugin into your CI pipeline to enforce Dockerfile security standards on every pull request. The plugin returns structured findings with severity levels, allowing you to fail builds on CRITICAL findings (like `curl | sh`) while allowing LOW findings (like missing multi-stage builds) as warnings. This prevents the most dangerous container misconfigurations from reaching production.

### Container Security Baseline

Your organization is adopting containers and needs to establish a security baseline. Run this plugin across all repositories to inventory every Dockerfile security issue. The 12 rules cover the CIS Docker Benchmark recommendations for Dockerfile security, giving your security team a starting point for container hardening standards.

### Pre-Deployment Audit

Before promoting container images to production, run this plugin to verify that no sensitive files (`.env`, SSH keys, AWS credentials) have been copied into the image, no secrets are hardcoded in ENV instructions, and the container does not run as root. These checks catch the most impactful container security issues that are easy to introduce and difficult to detect without automated scanning.

### Developer Education

When a developer creates a new Dockerfile, this plugin provides immediate feedback on security best practices. The finding messages include specific remediation guidance (e.g., "use COPY instead of ADD for local files," "consider adding a USER instruction to avoid running as root"), making it an educational tool as well as a security gate.

## 5-Minute Demo

### Prerequisites

- Go 1.25+
- [Nox](https://github.com/Nox-HQ/nox) installed

### Quick Start

1. **Install the plugin**

   ```bash
   nox plugin install Nox-HQ/nox-plugin-container
   ```

2. **Create a test Dockerfile** (`demo/Dockerfile`):

   ```dockerfile
   FROM node

   ENV DATABASE_PASSWORD=supersecret123
   ENV API_KEY=sk-prod-abc123xyz

   RUN apt-get update && apt-get install -y curl
   RUN curl https://example.com/setup.sh | sh

   ADD app.tar.gz /app
   COPY .env /app/.env
   COPY id_rsa /root/.ssh/id_rsa

   RUN chmod 777 /app/data
   RUN sudo npm install -g pm2

   EXPOSE 22 3389 8080

   CMD ["node", "server.js"]
   ```

3. **Run the scan**

   ```bash
   nox scan --plugin nox/container demo/
   ```

4. **Review findings**

   ```
   nox-plugin-container: 11 findings

   CONTAINER-001 [HIGH] Container running as root: no USER instruction found:
     consider adding a USER instruction to avoid running as root
     demo/Dockerfile:1:1
     cwe: CWE-250

   CONTAINER-002 [MEDIUM] Using latest tag or untagged base image: base image
     has no explicit tag, defaults to :latest
     demo/Dockerfile:1:1
     cwe: CWE-829

   CONTAINER-009 [HIGH] Secret or credential set via ENV instruction: secret
     value hardcoded in ENV instruction; use build args or secrets mount
     demo/Dockerfile:3:3
     cwe: CWE-798

   CONTAINER-009 [HIGH] Secret or credential set via ENV instruction: secret
     value hardcoded in ENV instruction; use build args or secrets mount
     demo/Dockerfile:4:4
     cwe: CWE-798

   CONTAINER-007 [LOW] Package manager cache not cleaned after install:
     apt-get install without cache cleanup (apt-get clean / rm -rf /var/lib/apt)
     demo/Dockerfile:6:6
     cwe: CWE-459

   CONTAINER-008 [CRITICAL] Remote script piped to shell (curl|sh pattern):
     curl output piped directly to shell
     demo/Dockerfile:7:7
     cwe: CWE-94

   CONTAINER-004 [LOW] ADD instruction used instead of COPY: use COPY instead
     of ADD for local files
     demo/Dockerfile:9:9
     cwe: CWE-829

   CONTAINER-003 [HIGH] Sensitive file copied into container image: sensitive
     file being copied into container
     demo/Dockerfile:10:10
     cwe: CWE-200

   CONTAINER-003 [HIGH] Sensitive file copied into container image: sensitive
     file being copied into container
     demo/Dockerfile:11:11
     cwe: CWE-200

   CONTAINER-010 [MEDIUM] Overly permissive file permissions (chmod 777):
     chmod 777 grants excessive permissions
     demo/Dockerfile:13:13
     cwe: CWE-732

   CONTAINER-012 [MEDIUM] Use of sudo in RUN instruction: sudo is unnecessary
     in containers; run commands directly or use USER
     demo/Dockerfile:14:14
     cwe: CWE-250
   ```

## Rules

| ID | Description | Severity | Confidence | CWE |
|----|-------------|----------|------------|-----|
| CONTAINER-001 | Container running as root: no USER instruction found | High | High | CWE-250 |
| CONTAINER-002 | Using latest tag or untagged base image | Medium | High | CWE-829 |
| CONTAINER-003 | Sensitive file copied into container image | High | High | CWE-200 |
| CONTAINER-004 | ADD instruction used instead of COPY | Low | Medium | CWE-829 |
| CONTAINER-005 | Privileged or dangerous port exposed | Medium | Medium | CWE-284 |
| CONTAINER-006 | No multi-stage build detected in Dockerfile | Low | Medium | CWE-1104 |
| CONTAINER-007 | Package manager cache not cleaned after install | Low | Medium | CWE-459 |
| CONTAINER-008 | Remote script piped to shell (curl\|sh pattern) | Critical | High | CWE-94 |
| CONTAINER-009 | Secret or credential set via ENV instruction | High | Medium | CWE-798 |
| CONTAINER-010 | Overly permissive file permissions (chmod 777) | Medium | High | CWE-732 |
| CONTAINER-011 | No HEALTHCHECK instruction defined | Low | High | CWE-693 |
| CONTAINER-012 | Use of sudo in RUN instruction | Medium | High | CWE-250 |

### Sensitive File Patterns (CONTAINER-003)

The following file patterns trigger a sensitive file detection when used with COPY or ADD instructions:

`.env`, `.ssh`, `.aws`, `id_rsa`, `.gnupg`, `credentials`, `.secret`, `.key`, `.pem`, `.p12`, `.pfx`

### Privileged Ports (CONTAINER-005)

The following ports are flagged as privileged or dangerous when used in EXPOSE instructions:

| Port | Service |
|------|---------|
| 21, 22 | FTP, SSH |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS |
| 110 | POP3 |
| 139, 445 | SMB/NetBIOS |
| 3389 | RDP |

### ENV Secret Patterns (CONTAINER-009)

ENV instructions with variable names containing: `PASSWORD`, `SECRET`, `TOKEN`, `KEY`, `API_KEY`, `PRIVATE_KEY`

### Dockerfile Detection

Files are identified as Dockerfiles if they match any of these patterns:
- Exact name: `Dockerfile`
- Prefixed: `Dockerfile.*` (e.g., `Dockerfile.prod`, `Dockerfile.dev`)
- Suffixed: `*.dockerfile` (e.g., `app.dockerfile`)

## Supported File Types

| File Type | Detection |
|-----------|-----------|
| `Dockerfile` | All 12 rules |
| `Dockerfile.*` | All 12 rules |
| `*.dockerfile` | All 12 rules |

This plugin does not scan source code by language. It exclusively analyzes Dockerfile syntax and instructions.

## Configuration

This plugin requires no configuration.

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| _None_ | This plugin has no environment variables | -- |

## Installation

### Via Nox (recommended)

```bash
nox plugin install Nox-HQ/nox-plugin-container
```

### Standalone

```bash
git clone https://github.com/Nox-HQ/nox-plugin-container.git
cd nox-plugin-container
go build -o nox-plugin-container .
```

## Development

```bash
# Build
go build ./...

# Run tests
go test ./...

# Run a specific test
go test ./... -run TestCurlPipeShell

# Lint
golangci-lint run

# Run in Docker
docker build -t nox-plugin-container .
docker run --rm nox-plugin-container
```

## Architecture

The plugin is built on the Nox plugin SDK and communicates via the Nox plugin protocol over stdio.

**Scan pipeline:**

1. **Workspace walk and Dockerfile discovery** -- Recursively traverses the workspace root, skipping `.git`, `vendor`, `node_modules`, `__pycache__`, and `.venv` directories. Each file is checked against the `isDockerfile` function, which matches `Dockerfile`, `Dockerfile.*` prefixes, and `*.dockerfile` suffixes (case-insensitive).

2. **Dockerfile parsing** -- The file is read line-by-line into `dockerfileLine` structs containing the line number and text content.

3. **Line continuation resolution** -- The `resolveLineContinuations` function merges lines ending with backslash (`\`) into the following line, preserving the original line number of the first line. This ensures multi-line RUN commands (common in Dockerfiles) are evaluated as complete instructions. Comments and empty lines within continuation blocks are skipped.

4. **Rule execution** -- All 12 rules are executed against the resolved lines. Each rule has a dedicated check function that receives the full set of resolved lines and returns a list of `ruleMatch` structs with line numbers and diagnostic messages. Rules fall into three categories:
   - **Global checks** (CONTAINER-001, CONTAINER-006, CONTAINER-011): Analyze the entire file for the presence or absence of specific instructions (USER, multiple FROM, HEALTHCHECK).
   - **Line-level checks** (CONTAINER-002, CONTAINER-003, CONTAINER-004, CONTAINER-005, CONTAINER-007, CONTAINER-008, CONTAINER-009, CONTAINER-010, CONTAINER-012): Match individual instructions against regex patterns.
   - **Composite checks** (CONTAINER-007): Match a pattern and verify the absence of a mitigation pattern on the same line (e.g., `apt-get install` without `apt-get clean`).

5. **Output** -- Each match produces a finding with the rule ID, severity, confidence, diagnostic message, file location, and CWE identifier as metadata.

## Contributing

Contributions are welcome. Please open an issue first to discuss proposed changes.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-dockerfile-check`)
3. Write tests for new Dockerfile security checks
4. Ensure `go test ./...` and `golangci-lint run` pass
5. Submit a pull request

## License

Apache-2.0
