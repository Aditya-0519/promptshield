# Security Policy

## Supported versions

Security fixes are currently provided for the latest version on the `main` branch. There are no separate supported release branches yet.

## Reporting a vulnerability

Please do not open a public issue containing an exploitable vulnerability, credentials, customer data, or an unredacted PromptShield report. Use GitHub's **Report a vulnerability** feature for this repository, or contact the maintainers privately through the contact method listed on the GitHub profile.

Include the affected version/commit, impact, reproduction steps, and a minimal proof of concept. Do not include real secrets or data belonging to another person.

## Safe use

PromptShield sends adversarial prompts to configured targets. Only scan systems you own or have explicit permission to test. Use staging environments and synthetic canaries. Reports may contain sensitive target responses; keep them private and retain default redaction unless full evidence is required in a controlled environment.
