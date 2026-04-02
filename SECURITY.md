# Security Policy

agent-inject takes security seriously. We welcome responsible disclosure of vulnerabilities in agent-inject itself and will work with you to address valid issues.

## Security Model

agent-inject is an offensive testing framework for AI agent systems. It runs locally with the operator's permissions and intentionally sends adversarial payloads to target agents. This is the tool's purpose, not a vulnerability.

**Trust model:**

- **Trusted inputs**: Configuration via environment variables or `.env` file, YAML attack payload files, CLI arguments (target URL, goal, attack names). Treat these the same way you would treat running a Python script locally.
- **Untrusted inputs**: HTTP responses from target agents. These are parsed by adapters and passed to scorers for pattern matching. Untrusted data should never trigger code execution, file access, or network activity beyond the configured target.

**Key security properties:**

- API keys are stored as `SecretStr` (pydantic) to prevent accidental logging or repr exposure
- YAML payload loading uses `yaml.safe_load()` exclusively -- no arbitrary code execution
- All domain objects use frozen dataclasses (immutable after creation)
- HTTP client timeouts are enforced (default 30 seconds)
- Concurrency is bounded by a configurable semaphore (1-50)

## Scope

### In Scope

Vulnerabilities in agent-inject's own code, dependencies, and supply chain:

- Code execution, file access, or network access triggered by **untrusted data** (target agent responses) without explicit operator configuration
- API key or credential leakage from agent-inject's own handling
- Path traversal or arbitrary file read/write from data-only inputs
- YAML deserialization vulnerabilities in the attack payload loader
- HTTP request smuggling or SSRF in adapters
- Supply chain attacks on agent-inject's PyPI package, GitHub Actions, or dependencies
- Bypasses of intended scope restrictions (attacking targets the operator did not configure)
- Vulnerabilities in CLI argument parsing, configuration validation, or output serialization
- Algorithmic complexity DoS (crafted input causing hang or crash with modest input size)

### Out of Scope

These are features, not bugs:

- Attack techniques and payloads that agent-inject enables -- these are the product
- Prompt injection methods in YAML payload files
- Issues requiring the operator to run untrusted configurations or payload files
- Network requests triggered by operator-controlled configuration (target URLs, API keys)
- Vulnerabilities discovered **by** agent-inject in target systems -- report those to the target system's maintainers
- Third-party dependency issues that do not materially affect agent-inject's security posture -- report those upstream
- Social engineering, phishing, or physical attacks
- Volumetric denial of service

**Examples of out-of-scope reports:**

- "agent-inject sends adversarial payloads to the target" -- That is the tool's purpose.
- "A YAML payload file contains a prompt injection" -- Payloads are features, not vulnerabilities.
- "agent-inject makes HTTP requests to the configured target URL" -- The operator controls the target.
- "The tool can be used to attack AI agents" -- That is the product description.

If you are unsure whether something is in scope, report it anyway. We would rather triage a borderline report than miss a real vulnerability.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | Yes (current)      |
| < 0.1   | No                 |

Security fixes are applied to the latest release only.

## Reporting a Vulnerability

**Preferred:** Report privately via GitHub Security Advisories.

[Report a vulnerability](https://github.com/isaacschepp/agent-inject/security/advisories/new)

**Do not** open a public GitHub issue with vulnerability details.

If GitHub's private reporting is inaccessible to you, open an issue with the title "Security report" and minimal details. We will contact you to coordinate private disclosure.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Impact assessment (what can an attacker achieve?)
- Suggested fix, if known
- Whether you would like credit

## Response Timeline

These are response targets, not service-level guarantees.

| Stage                      | Target             |
| -------------------------- | ------------------ |
| Acknowledgment             | 3 business days    |
| Initial assessment         | 7 business days    |
| Fix (Critical, 9.0-10.0)  | 14 calendar days   |
| Fix (High, 7.0-8.9)       | 30 calendar days   |
| Fix (Medium, 4.0-6.9)     | 60 calendar days   |
| Fix (Low, 0.1-3.9)        | Best effort        |

Severity is assessed using [CVSS v4.0](https://www.first.org/cvss/v4.0/specification-document), supplemented by agent-inject's trust model. Targets assume sufficient information to reproduce the issue and are not blocked on reporter follow-up or upstream fixes. We may ship mitigations or workarounds before a full fix is available and will communicate any material delays.

## Embargo and Disclosure

We follow a **90-day coordinated disclosure timeline**. We ask reporters to keep vulnerability details confidential until:

- A fix or mitigation is available, or
- We agree on a disclosure date

If remediation is delayed, we will keep the reporter informed and coordinate a revised timeline in good faith.

## CVE Policy

We request CVEs through GitHub Security Advisories when appropriate.

**We request a CVE for:**

- Remote code execution from untrusted inputs (target agent responses)
- Credential leakage to unconfigured or unintended destinations
- Supply chain compromise affecting the PyPI package or build artifacts

**Case-by-case:**

- Algorithmic DoS with significant resource impact
- Path traversal with demonstrable impact

**We generally do not request a CVE for:**

- Issues in operator-controlled configuration or payload files
- Attack payloads working as designed
- Quality, UX, or non-security functional bugs

We may still fix issues without requesting a CVE. This classification only affects whether we publish a formal advisory.

## Safe Harbor

We consider security research conducted in good faith to be authorized and will not initiate legal action against researchers who:

- Act in good faith and follow this policy
- Avoid privacy violations, data destruction, and service disruption
- Report vulnerabilities promptly and do not exploit them beyond what is necessary to demonstrate the issue
- Limit testing to agent-inject itself, not third-party services or other users' systems
- Do not perform social engineering, phishing, physical attacks, or volumetric denial-of-service testing

This safe harbor covers testing **agent-inject the tool**. It does not authorize using agent-inject to test systems you do not own or have explicit permission to test.

## Secrets Management

- **Application secrets**: API keys are loaded from environment variables
  (`AGENT_INJECT_` prefix) or `.env` files, never hardcoded. Stored in code as
  pydantic `SecretStr` to prevent accidental logging or repr exposure.
- **CI/CD secrets**: Managed via GitHub Actions encrypted secrets. PyPI
  publishing uses OIDC trusted publishing (no long-lived API tokens).
- **Detection**: GitHub secret scanning and push protection are enabled.
  Pre-commit hooks catch accidental credential commits.
- **Rotation**: If a secret is exposed, revoke immediately, rotate the
  credential, and audit git history for the exposure scope.
- **Source control**: `.env` files are excluded via `.gitignore`. Only
  `.env.example` (with placeholder values) is committed.

## Legal Notice

agent-inject is provided for authorized security testing only. Operators are responsible for obtaining proper authorization before testing target systems. This security policy covers vulnerabilities in agent-inject itself, not the use of agent-inject against target systems.
