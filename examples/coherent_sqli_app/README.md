# Coherent SQLi Demo Target (Demo Collateral)

Intentionally vulnerable Flask application used to demonstrate Mugiwara
Security's dynamic verification producing a genuine `VERIFIED` result inside
its Docker sandbox.

**Warning: do not deploy this application.** It exists solely as authorized
testing collateral for the Mugiwara demo. Only ever run and scan it locally
in an isolated environment.

## The vulnerability

`app.py` builds a SQLite query by string interpolation of the untrusted
`username` query parameter:

```python
cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
```

## Demo

```bash
# one-time: build the sandbox image with this target's dependencies
docker build -f docker/demo-sandbox.Dockerfile -t mugiwara-sandbox-py-demo:latest .

# scan with dynamic verification (mock LLM provider, real Docker sandbox)
uv run mugiwara scan examples/coherent_sqli_app --sandbox docker
```

Expected: `Verified by PoC: 1` — the `sql_injection` finding is confirmed by
a safety-screened Proof-of-Concept probe executed against the live target in
an ephemeral container, with attached evidence (canary token, HTTP trace,
execution logs).
