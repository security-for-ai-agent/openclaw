# @openclaw/security-intercept

Post-tool detection + same-outer-turn interception for prompt-injection and
shell-injection payloads. Implements **Case 1a** from the OpenClaw security
plugin design (`openclaw-security/discuss/plugin-design.md`).

## What it does

**Case 1a — tool-result origin** (every tool result that lands in the agent's
transcript):

1. **Detect** — synchronously match the result against regex patterns for
   prompt-injection and shell-injection (configurable).
2. **Intercept (content)** — replace the tool result with a `[BLOCKED]`
   placeholder before it reaches the LLM.
3. **Guide** — on the next inner LLM loop in the same outer turn, inject a
   `SECURITY ALERT` directive telling the LLM to notify the user and not
   retry.
4. **Intercept (control)** — block any follow-on tool call in the same
   `runId`.

**Case 1b — outbound egress scan** (every channel-bound reply, regardless of
whether it came from an LLM or from a memory-retrieval bypass):

5. **Redact** — replace credential-shaped or PII substrings in the reply with
   `[REDACTED:<kind>]` and append a security notice.
6. **Cancel** — if the reply contains a private-key PEM block, cancel the
   whole message and substitute a short security notice.

**Shared:**

7. **Audit** — contribute findings to `openclaw security audit` and
   `openclaw doctor`.

See `REQUIREMENTS.md` for line-by-line requirement → code traceability.

## Enable

```bash
openclaw config set plugins.entries.security-intercept.enabled true
openclaw config set plugins.entries.security-intercept.config.mode enforce
openclaw gateway restart
```

## Configure

```json
{
  "plugins": {
    "entries": {
      "security-intercept": {
        "enabled": true,
        "config": {
          "mode": "enforce",
          "threats": {
            "promptInjection": true,
            "shellInjection": true,
            "credentialLeak": true,
            "piiExposure": true
          },
          "patterns": {
            "promptInjection": ["additional-regex-1", "additional-regex-2"],
            "shellInjection": [],
            "credentialLeak": [],
            "piiExposure": []
          },
          "egress": {
            "action": "redact",
            "addNotice": true
          }
        }
      }
    }
  }
}
```

`mode` default is `"shadow"` — detect and audit without applying any
interception action. Flip to `"enforce"` once the operator has validated the
detection rate.

## Kill switch

```bash
OPENCLAW_SECURITY_OFF=1 openclaw ...
```

All hooks become no-ops and a `critical` finding appears in
`openclaw security audit`.

## Verify

```bash
openclaw plugins list | grep security-intercept
openclaw plugins inspect security-intercept
openclaw security audit --deep
```

## Scope

This plugin covers **Case 1a** (tool-result origin, `prompt-injection` /
`shell-injection`) and **Case 1b** (outbound egress scan for `credential-leak`
/ `pii-exposure` — catches the memory-retrieval bypass path). **Case 2**
(`prompt-modify` for tool-origin `credential-leak` / `scope-expansion` /
`oversized-result`) ships in the follow-on commit per the 2026-04-20 plan in
`openclaw-security/discuss/group-discuss-1.md`.
