# Secure Authentication Lab

A small local authentication service with safe password storage, server-side validation, rate limiting, and secure sessions, plus automated tests.

## Run the tests

```bash
pip install -r requirements.txt   # Flask (pytest optional)
python -m unittest discover -v    # or: pytest -v
```

## Run the service locally

```bash
python run.py
```

The session cookie is `Secure`, so use HTTPS (or a browser on `localhost`). With curl, pass the cookie header by hand:

```bash
curl -X POST localhost:5000/register -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"correct-horse-battery-staple"}'
curl -i -X POST localhost:5000/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"correct-horse-battery-staple"}'   # note Set-Cookie
curl localhost:5000/me -H 'Cookie: __Host-session=<token>'
```

## Layout

- `auth_lab/hashing.py`: scrypt hashing and verification
- `auth_lab/validation.py`: username and password rules
- `auth_lab/sessions.py`: server-side sessions
- `auth_lab/ratelimit.py`: sliding-window limiter
- `auth_lab/app.py`: routes, cookies, headers
- `tests/test_auth.py`: 39 tests
- `SECURITY_NOTE.md`: threat model, controls, limitations
- `TEST_OUTPUT.txt`: saved test run

## Submitting

Push to GitHub (no secrets are in the repo; `.gitignore` excludes databases and `.env`), set it to public or view-only, and submit the repo URL. Everything the checker needs is in this one repo.
