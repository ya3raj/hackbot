# Bounded federation API

HackBot exposes a loopback-only, versioned control surface for UltraHackAgentBot:

- `GET /api/federation/v1/capabilities`
- `POST /api/federation/v1/ai/one-shot`
- `POST /api/federation/v1/osint/full`
- `POST /api/federation/v1/cancel`

These are not unauthenticated GUI endpoints. Set a fresh high-entropy token in
the HackBot process and send the same value as `X-UltraHackBot-Token` on every
request:

```bash
export ULTRAHACKBOT_HACKBOT_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
hackbot gui
```

Missing, malformed, or mismatched tokens return a generic `401` before provider
or OSINT work begins; valid tokens are compared in constant time. The bounded AI operation performs one tool-free call with
no fallback or retry. The bounded OSINT operation accepts one public bare FQDN,
verifies TLS, ignores ambient proxies, blocks cross-origin redirects, and applies
one deadline plus item and response-size ceilings. Cancellation is cooperative
and request IDs are bounded and process-local.

Treat the token like a credential: keep it out of configuration files, command
output, reports, and federation ledgers, and rotate it whenever either process
restarts.
