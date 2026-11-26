# Security policy

Please report vulnerabilities privately through
[GitHub security advisories](https://github.com/pavankalyan-Maturi/mcp-sentinel/security/advisories/new)
rather than a public issue. You should get a reply within a few days.

## Scope and limits

mcp-sentinel is a defence-in-depth layer. Keep these limits in mind:

- **Prompt-injection detection is heuristic.** It catches common attack
  patterns, not every possible one. Use least-privilege policies and human
  approval for destructive tools; don't rely on detection alone.
- **Redaction is pattern-based.** Secrets in unusual formats can slip through;
  add `custom_patterns` for formats specific to your organisation.
- **Agent identity is only as strong as its source.** With `wrap`, whoever
  launches the proxy chooses `--agent`. With `serve`, configure `token_env` so
  the `X-Sentinel-Agent` header alone is not trusted.
