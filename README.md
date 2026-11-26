# PromptShield

Open-source security scanner for LLM-powered apps. Point it at a chatbot or agent endpoint and it fires a
library of attacks (prompt injection, system prompt leaks, data leaks) and reports what broke, the exact
prompt that broke it, and how to fix it.

Zero dependencies. Needs Node 18+.

## Quick start

```bash
# terminal 1: start the deliberately vulnerable test bot (mock mode, no API key needed)
node vulnerable-bot/server.js

# terminal 2: scan it
node src/cli.js scan --config promptshield.config.json
# open reports/report.html
```

Use a real Gemini-backed target and an LLM judge:

```bash
export GEMINI_API_KEY=your_key
node vulnerable-bot/server.js                         # now backed by Gemini
node src/cli.js scan --config promptshield.config.json --llm-judge
```

## Scan your own app

Edit `promptshield.config.json`:

| Field | Meaning |
|---|---|
| `url`, `method`, `headers` | Where and how to call your chat endpoint |
| `bodyTemplate` | Request body; `{{prompt}}` is replaced by each attack |
| `responsePath` | Dot path to the reply text in the JSON response (e.g. `reply` or `choices.0.message.content`) |
| `secrets` | Strings that must never appear in a response (API keys, internal codes, phrases from your system prompt) |
| `delayMs`, `timeoutMs` | Pacing and timeout |

Only scan apps you own or have written permission to test.

## Provenance and INCONCLUSIVE results

A scan is only trustworthy if the target really called a live model. Targets can report this with an
`X-AI-Provenance: live | mock | fallback | none` header or a `provenance.source` body field
(ABTalks does this when `EXPOSE_AI_PROVENANCE=true`). Optional config:

| Field | Meaning |
|---|---|
| `requireProvenance` | `true`: a response with no provenance is INCONCLUSIVE (recommended for LLM targets) |
| `provenanceHeader` | Header name (default `x-ai-provenance`) |
| `provenancePath` | Body dot path (default `provenance.source`) |

Verdicts: `vulnerable` (confirmed), `safe` (attack really ran and nothing was found), `inconclusive`
(HTTP error, timeout, network error, mock or fallback response, or missing provenance when required).
A protected canary appearing in output is always reported as vulnerable. Inconclusive is never safe.

## How judging works

1. Rules: any `secrets` string in the response is an automatic fail; attacks can also define marker strings and regex patterns.
2. Optional LLM judge (`--llm-judge`): Gemini reviews the response to catch subtle leaks and cut false positives.

The CLI exits with code 1 when something is vulnerable, so you can run it in CI.

## Add attacks

Drop objects into any file in `attacks/`:

```json
{
  "id": "INJ-007", "category": "prompt_injection", "severity": "high",
  "name": "Short name",
  "prompt": "The attack text",
  "detect": { "contains_any": ["MARKER"], "regex": ["optional pattern"] },
  "fix": "How to fix it"
}
```

## Roadmap

- Multi-turn attacks and tool/agent abuse tests
- OWASP LLM Top 10 mapping in reports
- GitHub Action, web dashboard, scheduled scans