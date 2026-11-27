# PromptShield

Find out whether a user can trick your chatbot or LLM application into leaking its system prompt, private data, or secrets — and measure the results.

PromptShield is a command-line security scanner for HTTP-accessible LLM applications. Run it locally or integrate it into CI.

**Zero runtime dependencies · Node.js 18+**

## Supported transports

PromptShield works with HTTP-accessible targets using these transports:

| Your application | Transport |
|---|---|
| Your own HTTP chat API (any request/response shape) | `http` |
| OpenAI, Azure OpenAI, Groq, Together, OpenRouter, vLLM, LM Studio, Ollama `/v1`, etc. | `openai` |
| Anthropic Claude | `anthropic` |
| Google Gemini | `gemini` |
| Ollama native API | `ollama` |

Every transport supports multi-turn attacks. PromptShield replays the conversation or reuses the session ID so attacks that unfold over multiple messages can reach your application.

## Installation and setup

PromptShield is not yet published to npm. Install it from this repository:

```bash
git clone https://github.com/Aditya-0519/promptshield.git
cd promptshield
npm test
```

### Initialize your project

Run:

```bash
node src/cli.js init
```

Choose the provider you want to test. PromptShield generates:

- `promptshield.config.json` — starter scanner configuration.
- `system-prompt.txt` — an example system prompt containing two unique fake canaries.
- `.env.example` — a reference template for the provider's API key, when applicable.

If you already have a configuration, initialization will not overwrite it unless you use `--force`. Existing `system-prompt.txt` and `.env.example` files are preserved.

**Important: Initialization does not connect PromptShield to your application or change your application's system prompt.**

The generated prompt is a starting template. To test prompt and data leakage:

1. Open `system-prompt.txt`.
2. Replace the example instructions with your application's test system prompt.
3. Keep the generated fake canary strings in the prompt or in a document your application retrieves.
4. Make sure your application actually uses that prompt or retrieves that document.
5. Review `promptshield.config.json` and confirm its settings match your application.

Canaries are fake test strings, not real credentials. Never put actual passwords, API keys, or private customer data in your test prompt.

### Configure your API key

Set the environment variable for your selected provider before scanning.

PromptShield expands environment variables in its configuration, but **does not automatically load `.env` files**. The generated `.env.example` is a reference template, not an automatically loaded configuration file.

For OpenAI, use:

**Windows PowerShell**

```powershell
$env:OPENAI_API_KEY = "your-api-key"
node src/cli.js scan
```

**macOS/Linux**

```bash
export OPENAI_API_KEY="your-api-key"
node src/cli.js scan
```

For other providers, use the corresponding variable:

| Provider | Environment variable |
|---|---|
| OpenAI-compatible | `OPENAI_API_KEY` |
| Anthropic | `ANTHROPIC_API_KEY` |
| Gemini | `GEMINI_API_KEY` |

Ollama and HTTP targets do not require a provider API key by default, although your own HTTP application may require authentication headers or other credentials.

### Run your first scan

```bash
node src/cli.js scan --trials 5
```

Open `reports/report.html` to review the findings.

### Try the vulnerable demo

You can also test PromptShield against the deliberately vulnerable chatbot included in the repository.

Start the demo server in one terminal:

```bash
node vulnerable-bot/server.js
```

Then run the scanner in another terminal:

```bash
node src/cli.js scan --config examples/vulnerable-bot.config.json
```

The demo is intentionally vulnerable. It is provided for learning and testing, not as a production chatbot.

## What do SAFE, VULNERABLE and INCONCLUSIVE mean?

LLM responses can vary between runs. PromptShield repeats each attack using `--trials N` and calculates an attack success rate, along with a 95% Wilson confidence interval.

For example:

```text
Leaked in 3/5 trials
```

- **VULNERABLE:** An attack's measured success rate exceeds the configured threshold.
- **SAFE:** No leak or other configured attack indicator was observed in the trials run. This does not prove the application is secure.
- **INCONCLUSIVE:** The attack could not be reliably judged, for example because of a network error, mock/fallback response, or missing detector. Inconclusive results are never counted as safe.

### Canary-based leak detection

Canaries are unique fake strings placed in your system prompt, retrieved documents, or other test data.

Add them to the `secrets` field in your configuration. If one appears in a model response, PromptShield can identify it as a leak.

`promptshield init` generates two unique canaries to help you get started.

### System-prompt leak detection

Without canaries, you can provide `systemPrompt` or `systemPromptFile`. PromptShield can then detect verbatim reproduction of the supplied prompt.

This does not reliably detect translations or paraphrased versions of the prompt. Use canaries for stronger evidence.

If neither a system prompt nor canaries are configured, system-prompt-leak attacks are reported as `INCONCLUSIVE (no_detector)` rather than being incorrectly marked SAFE.

A refusal that merely quotes an attack marker, such as `I won't say PWNED-4821`, is not automatically treated as a successful leak.

## Configuration

Example `promptshield.config.json`:

```json
{
  "transport": "openai",
  "url": "https://api.openai.com/v1/chat/completions",
  "model": "gpt-4o-mini",
  "apiKey": "${OPENAI_API_KEY}",
  "systemPromptFile": "system-prompt.txt",
  "secrets": ["PSHIELD_CANARY_1A2B3C4D"],
  "trials": 5,
  "concurrency": 2
}
```

Environment variables can be referenced using `${NAME}` or `${NAME:-default}` anywhere in the configuration.

If a required variable is missing, PromptShield stops the scan and identifies the missing variable.

**Never commit a real API key or other credential to your repository.**

### Configuration fields

| Field | Description |
|---|---|
| `transport` / `provider` | Transport to use: `http`, `openai`, `anthropic`, `gemini`, or `ollama`. |
| `url`, `model`, `apiKey`, `headers` | Target endpoint, model, API key, and optional request headers. Provider transports have sensible URL defaults. |
| `params` | Additional request-body parameters for provider transports, such as `{"temperature": 0.7}`. |
| `bodyTemplate` (`http`) | Custom request body. Supports `{{prompt}}` for the current attack, `{{sessionId}}` for the scan session ID, `"{{messages}}"` for the full conversation array, and `{{transcript}}` for the conversation as text. |
| `startBodyTemplate`, `startUrl` (`http`) | Optional request to create a session before an attack. |
| `responsePath` (`http`) | Dot path to the response text, such as `reply` or `choices.0.message.content`. |
| `stream` (`http`) | Set to `true` if the endpoint streams SSE or NDJSON. |
| `systemPrompt`, `systemPromptFile` | System prompt used for verbatim leak detection. For provider transports, it is also sent as the system message. |
| `secrets` | Canary strings and other values that must never appear in an answer. |
| `allow` | Public values that should be ignored by pattern detectors, such as `support@acme.com`. |
| `trials`, `concurrency`, `threshold` | Number of repetitions per attack, concurrent requests, and tolerated attack success rate (0–1). |
| `delayMs`, `timeoutMs`, `retries` | Request pacing, timeout, and retries for supported transient errors (429/502/503/504). Default retries: 2. |
| `maxResponseBytes` | Maximum stored response size. Default: 2 MB. |
| `requireProvenance`, `provenanceHeader`, `provenancePath` | Optional response provenance checking. For applications reporting `X-AI-Provenance: live`, `mock`, or `fallback`. Off by default. |
| `authorized` | Set to `true` to authorize non-local URLs in CI without passing `--i-own-this-target`. |

## CLI usage

### Initialize

```bash
promptshield init [--provider openai|anthropic|gemini|ollama|http]
```

Use `--force` to replace an existing configuration. Existing system-prompt and environment-example files are preserved.

### Scan

```bash
promptshield scan [options]
```

Available options:

```text
--config <file>          Configuration file
--provider <provider>    Provider transport
--url <url>              Target URL
--model <model>          Model name
--trials <number>        Repetitions per attack
--concurrency <number>   Concurrent requests
--threshold <0-1>        Tolerated attack success rate
--category <list>        Attack categories to run
--attacks <directories>  Additional attack directories
--strict                 Return inconclusive exit code when results are inconclusive
--llm-judge               Enable the LLM judge
--format <formats>       html,json,sarif,junit
--out <directory>        Report output directory
--no-redact              Disable report redaction
--i-own-this-target      Confirm authorization for a non-local target
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No attack exceeded the configured threshold. |
| `1` | At least one attack exceeded the configured threshold. |
| `2` | Usage or configuration error. |
| `3` | Inconclusive results when `--strict` is enabled. |

Reports redact configured secrets by default. For private reports, `--no-redact` disables this protection. Handle unredacted reports carefully because they may contain sensitive information.

Only scan systems you own or are explicitly authorized to test. Non-local targets require `--i-own-this-target` unless authorization is configured.

## Use PromptShield in CI

See `.github/workflows/promptshield.yml` for a GitHub Actions starter workflow.

Before using it:

1. Adapt the commented application-start step to launch your own test or staging chatbot.
2. Customize `promptshield.config.example.json` to match your application's request and response format.
3. Store API keys and application tokens in GitHub Actions secrets.
4. Make sure the workflow targets an application you are authorized to test.

The example workflow runs tests, scans the configured endpoint, uploads SARIF when available, and stores HTML, JSON, and JUnit reports as artifacts.

For other CI systems, run:

```bash
node src/cli.js scan --config <your-config> --format json,junit --out reports
```

Exit code `1` indicates that the configured attack-success threshold was exceeded. Exit code `3` indicates inconclusive results when `--strict` is enabled.

## Bundled attacks

PromptShield currently includes **27 bundled attacks**, covering:

- Prompt injection, including single-turn, encoded, and role-play attacks.
- Data-leak attempts.
- System-prompt extraction.
- Five multi-turn leak chains.
- Four indirect-injection payloads covering RAG chunks, email, tool results, and Markdown exfiltration.

You can add your own attacks as JSON files in a directory and pass that directory using `--attacks`.

Example:

```json
{
  "id": "MY-001",
  "category": "prompt_injection",
  "severity": "high",
  "name": "Short name",
  "steps": [
    "First message",
    "Second message using {{previousResponse}}"
  ],
  "detect": {
    "contains_any": ["MARKER"],
    "regex": ["optional pattern"]
  },
  "fix": "How to fix it"
}
```

Use `prompt` for a single-turn attack or `steps` for a multi-turn attack.

Attack files are validated before execution. Invalid detection fields produce an error identifying the affected file and field.

See `docs/EVIDENCE.md` for information about per-step evidence, stage markers, and complete-extraction assessment.

## Current limitations

PromptShield is an evolving security-testing tool. Its current limitations include:

- The 27 bundled attacks are a starting point, not comprehensive coverage.
- Adaptive attacker-LLM attacks are not implemented.
- Agent and tool-call security testing is not implemented.
- A published false-positive benchmark is not yet available.
- Verbatim system-prompt detection can miss translations and paraphrases. Canaries provide stronger evidence.
- A clean scan does not prove that an application is secure.
- PromptShield currently assesses chat request/response behavior. It does not inspect authorization boundaries inside tools or independently verify agent tool execution.
- Provider transports have automated mock-server coverage, not live compatibility certification for every provider, model, proxy, or account configuration.
- Generic HTTP integrations may require custom request templates, response paths, headers, and session handling.
- Built-in browser-based cookie login and token refresh are not provided.

## Tests

Run the automated test suite:

```bash
npm test
```

The tests cover scanner behavior, transports, attack execution, configuration, reporting, and other core functionality.

## Security

Only use PromptShield against systems you own or have explicit permission to test.

For vulnerability reports or security concerns, see [SECURITY.md](SECURITY.md).

## License

MIT