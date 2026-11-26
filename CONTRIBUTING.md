# Contributing

```bash
git clone https://github.com/pavankalyan-Maturi/mcp-sentinel
cd mcp-sentinel
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,langgraph]"

pytest -q                         # unit + integration tests (spawn real proxy processes)
ruff check src tests examples     # lint
ruff format src tests examples    # format
mypy src                          # strict type-check
```

Guidelines:

- Every behaviour change needs a test. Proxy changes need an integration test
  in `tests/test_stdio_proxy.py` or `tests/test_http_proxy.py`.
- New scanner detectors need a positive test *and* a false-positive test.
- Fail closed: when something goes wrong in a security path, block the call.
- Never write a raw secret to logs, audit rows, approval prompts, or excerpts.

Releases: see [RELEASING.md](RELEASING.md).
