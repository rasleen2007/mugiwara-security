# Sample Vulnerable App (fixture)

Intentionally vulnerable demo service used by Phase 3 agent tests.
Stack: Python 3.11, Flask 2.x, SQLite via the standard library sqlite3 module.

## Endpoints

- `/ping` - health probe declared as POST in code
- `/users` - list users filtered by an unfiltered query parameter

This directory is test data only; never deploy or run it.
