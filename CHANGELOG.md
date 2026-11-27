# Changelog

## 0.2.2 - 2026-11-27

- Improved the init workflow with automatic starter system-prompt generation.
- Generated unique fake canaries for prompt and data leak detection.
- Added provider-specific `.env.example` templates.
- Preserved existing system prompt and environment example files.
- Added safe config overwrite behavior through `--force`.
- Improved setup instructions for API keys and local scanning.
- Expanded init tests to cover file creation, preservation and forced configuration replacement.

## 0.2.1 - 2026-11-27

- Hardened HTTP requests by refusing redirects, preventing a configured target from silently redirecting scan prompts or credentials to another host.
- Applied the non-local target authorization check to both the primary URL and optional session start URL.
- Validated target URLs as HTTP/HTTPS and rejected embedded URL credentials.
- Corrected the SARIF repository information URI.
- Reworked the GitHub Actions example to run the repository's local CLI rather than assuming the package is already published to npm.
- Added a public example config, security policy, and release notes.
- Clarified source-install instructions and current product limitations.
