import os
import re
import sqlite3
import tempfile
import unittest

from auth_lab import create_app, hashing, validation
from auth_lab.app import COOKIE_NAME, GENERIC_LOGIN_ERROR

GOOD_PW = "correct-horse-battery-staple"


class FakeClock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


class Base(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.clock = FakeClock()
        self.app = create_app({"DB_PATH": self.db_path, "CLOCK": self.clock, "TESTING": True})
        # https base_url so Secure cookies behave as in production; cookies are
        # sent manually below so each test controls exactly what is replayed.
        self.client = self.app.test_client(use_cookies=False)

    def tearDown(self):
        os.unlink(self.db_path)

    def call(self, method, path, body=None, token=None, ip="203.0.113.10", **kw):
        headers = {"Cookie": f"{COOKIE_NAME}={token}"} if token else {}
        kwargs = dict(base_url="https://localhost", headers=headers,
                      environ_overrides={"REMOTE_ADDR": ip})
        if body is not None:
            kwargs["json"] = body
        kwargs.update(kw)
        return getattr(self.client, method)(path, **kwargs)

    def register(self, username="alice", password=GOOD_PW, **kw):
        return self.call("post", "/register", {"username": username, "password": password}, **kw)

    def login(self, username="alice", password=GOOD_PW, **kw):
        return self.call("post", "/login", {"username": username, "password": password}, **kw)

    @staticmethod
    def token_from(resp):
        for header in resp.headers.getlist("Set-Cookie"):
            m = re.match(rf"{re.escape(COOKIE_NAME)}=([^;]*)", header)
            if m:
                return m.group(1)
        return None

    def login_token(self, **kw):
        self.register()
        resp = self.login(**kw)
        self.assertEqual(resp.status_code, 200)
        return self.token_from(resp)


# --- Step 1: password hashing and server-side validation -------------------
class TestPasswordHashing(unittest.TestCase):
    def test_hash_is_not_plaintext_and_uses_scrypt(self):
        h = hashing.hash_password(GOOD_PW)
        self.assertTrue(h.startswith("scrypt$"))
        self.assertNotIn(GOOD_PW, h)

    def test_salts_are_unique(self):
        self.assertNotEqual(hashing.hash_password(GOOD_PW), hashing.hash_password(GOOD_PW))

    def test_verify_correct_and_wrong(self):
        h = hashing.hash_password(GOOD_PW)
        self.assertTrue(hashing.verify_password(GOOD_PW, h))
        self.assertFalse(hashing.verify_password(GOOD_PW + "x", h))

    def test_malformed_hash_fails_closed(self):
        for bad in ("", "garbage", "scrypt$1$2$3$a$b", "md5$16384$8$1$AA==$AA==",
                    "scrypt$999999999$8$1$AA==$AA=="):
            self.assertFalse(hashing.verify_password(GOOD_PW, bad))

    def test_needs_rehash_detects_weaker_parameters(self):
        weak = hashing.hash_password(GOOD_PW, n=2**10)
        self.assertTrue(hashing.needs_rehash(weak))
        self.assertFalse(hashing.needs_rehash(hashing.hash_password(GOOD_PW)))


class TestValidation(unittest.TestCase):
    def test_rejects_short_password(self):
        self.assertTrue(validation.validate_password("short1!"))

    def test_rejects_overlong_password(self):
        self.assertTrue(validation.validate_password("a1" * 100))

    def test_rejects_common_and_repetitive(self):
        self.assertTrue(validation.validate_password("password12345"))
        self.assertTrue(validation.validate_password("aaaaaaaaaaaaaaaa"))

    def test_rejects_password_containing_username(self):
        self.assertTrue(validation.validate_password("my-alice-secret-pass", "alice"))

    def test_rejects_non_string_types(self):
        self.assertTrue(validation.validate_password(123456789012))
        self.assertTrue(validation.validate_username(["alice"]))
        self.assertTrue(validation.validate_username(None))

    def test_username_format(self):
        for bad in ("ab", "a" * 33, "bad name", "x;DROP", "<script>", "é" * 5):
            self.assertTrue(validation.validate_username(bad), bad)
        self.assertEqual(validation.validate_username("alice_01"), [])

    def test_accepts_strong_password(self):
        self.assertEqual(validation.validate_password(GOOD_PW, "alice"), [])


class TestRegistration(Base):
    def test_register_success_stores_only_a_hash(self):
        self.assertEqual(self.register().status_code, 201)
        row = sqlite3.connect(self.db_path).execute("SELECT password_hash FROM users").fetchone()
        self.assertNotIn(GOOD_PW, row[0])
        self.assertTrue(row[0].startswith("scrypt$"))

    def test_register_rejects_weak_input_via_api(self):
        resp = self.register(password="short")
        self.assertEqual(resp.status_code, 400)
        self.assertTrue(resp.get_json()["errors"])
        self.assertEqual(self.register(username="bad name!").status_code, 400)

    def test_duplicate_username_case_insensitive(self):
        self.register()
        self.assertEqual(self.register(username="ALICE").status_code, 409)

    def test_non_json_and_wrong_types_rejected(self):
        resp = self.client.post("/register", data="username=a", base_url="https://localhost")
        self.assertEqual(resp.status_code, 415)
        self.assertEqual(self.call("post", "/register", ["x"]).status_code, 400)
        self.assertEqual(self.call("post", "/register", {"username": 5, "password": 6}).status_code, 400)

    def test_oversized_body_rejected(self):
        resp = self.call("post", "/register", {"username": "alice", "password": "a" * 10000})
        self.assertEqual(resp.status_code, 413)

    def test_registration_is_rate_limited_per_ip(self):
        for i in range(10):
            self.register(username=f"user{i:02d}")
        resp = self.register(username="user99")
        self.assertEqual(resp.status_code, 429)
        self.assertIn("Retry-After", resp.headers)


# --- Step 2: secure cookies, logout, session expiry ------------------------
class TestSessions(Base):
    def test_cookie_security_attributes(self):
        self.register()
        cookie = self.login().headers.get("Set-Cookie")
        self.assertTrue(cookie.startswith(COOKIE_NAME + "="))  # __Host- prefix
        self.assertIn("HttpOnly", cookie)
        self.assertIn("Secure", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertIn("Path=/", cookie)
        self.assertIn("Max-Age=", cookie)
        self.assertNotIn("Domain", cookie)  # required by the __Host- prefix

    def test_token_is_long_random_and_unique(self):
        self.register()
        t1 = self.token_from(self.login())
        t2 = self.token_from(self.login())
        self.assertGreaterEqual(len(t1), 40)
        self.assertNotEqual(t1, t2)

    def test_session_token_stored_hashed(self):
        token = self.login_token()
        rows = sqlite3.connect(self.db_path).execute("SELECT token_hash FROM sessions").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertNotEqual(rows[0][0], token)

    def test_me_requires_valid_session(self):
        self.assertEqual(self.call("get", "/me").status_code, 401)
        self.assertEqual(self.call("get", "/me", token="forged-token").status_code, 401)
        token = self.login_token()
        resp = self.call("get", "/me", token=token)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["username"], "alice")

    def test_logout_invalidates_session_server_side(self):
        token = self.login_token()
        resp = self.call("post", "/logout", {}, token=token)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Expires=Thu, 01 Jan 1970", resp.headers.get("Set-Cookie"))
        # replaying the OLD cookie must fail: the server forgot the session
        self.assertEqual(self.call("get", "/me", token=token).status_code, 401)

    def test_logout_without_session_is_harmless(self):
        self.assertEqual(self.call("post", "/logout", {}).status_code, 200)

    def test_idle_timeout(self):
        token = self.login_token()
        self.clock.advance(14 * 60)
        self.assertEqual(self.call("get", "/me", token=token).status_code, 200)  # slides timer
        self.clock.advance(16 * 60)
        self.assertEqual(self.call("get", "/me", token=token).status_code, 401)

    def test_absolute_timeout_even_if_active(self):
        token = self.login_token()
        elapsed = 0
        while elapsed < 8 * 3600 - 14 * 60:  # stay active (under the idle limit) for ~8h
            self.clock.advance(14 * 60)
            elapsed += 14 * 60
            self.assertEqual(self.call("get", "/me", token=token).status_code, 200)
        self.clock.advance(14 * 60)  # now past the 8h absolute cap
        self.assertEqual(self.call("get", "/me", token=token).status_code, 401)

    def test_login_rotates_session_prevents_fixation(self):
        old = self.login_token()
        new = self.token_from(self.login())
        self.assertNotEqual(old, new)
        self.assertEqual(self.call("get", "/me", token=old).status_code, 401)
        self.assertEqual(self.call("get", "/me", token=new).status_code, 200)

    def test_attacker_chosen_token_is_not_adopted(self):
        self.register()
        resp = self.call("post", "/login", {"username": "alice", "password": GOOD_PW}, token="attacker-chosen")
        self.assertNotEqual(self.token_from(resp), "attacker-chosen")
        self.assertEqual(self.call("get", "/me", token="attacker-chosen").status_code, 401)

    def test_security_headers_present(self):
        h = self.call("get", "/me").headers
        self.assertEqual(h["Cache-Control"], "no-store")
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'none'", h["Content-Security-Policy"])


# --- Step 3: rate limits and generic errors --------------------------------
class TestGenericErrors(Base):
    def test_unknown_user_and_wrong_password_look_identical(self):
        self.register()
        wrong_pw = self.login(password="not-the-right-password")
        no_user = self.login(username="nobody")
        self.assertEqual(wrong_pw.status_code, 401)
        self.assertEqual(no_user.status_code, 401)
        self.assertEqual(wrong_pw.get_json(), no_user.get_json())
        self.assertEqual(wrong_pw.get_json()["error"], GENERIC_LOGIN_ERROR)
        self.assertNotIn("Set-Cookie", wrong_pw.headers)

    def test_malformed_login_bodies_get_same_generic_error(self):
        for body in ({"username": None, "password": None}, {"username": 1, "password": 2},
                     {"username": "x" * 500, "password": "y"}, {}):
            resp = self.call("post", "/login", body)
            self.assertEqual((resp.status_code, resp.get_json()["error"]), (401, GENERIC_LOGIN_ERROR))

    def test_errors_do_not_leak_internals(self):
        text = self.login(username="nobody").get_data(as_text=True)
        for leak in ("Traceback", "sqlite", "scrypt", "File \""):
            self.assertNotIn(leak, text)


class TestRateLimiting(Base):
    def fail(self, n, username="alice", ip="203.0.113.10"):
        return [self.login(username=username, password="wrong-password-123", ip=ip).status_code
                for _ in range(n)]

    def test_account_locks_after_five_failures_even_with_correct_password(self):
        self.register()
        self.assertEqual(self.fail(5), [401] * 5)
        resp = self.login()  # correct password, but throttled
        self.assertEqual(resp.status_code, 429)
        self.assertGreater(int(resp.headers["Retry-After"]), 0)
        self.assertNotIn("Set-Cookie", resp.headers)

    def test_lockout_expires_after_window(self):
        self.register()
        self.fail(5)
        self.clock.advance(15 * 60 + 5)
        self.assertEqual(self.login().status_code, 200)

    def test_unknown_usernames_are_throttled_too(self):
        self.assertEqual(self.fail(5, username="ghost"), [401] * 5)
        self.assertEqual(self.fail(1, username="ghost"), [429])

    def test_lockout_applies_across_ips_for_same_account(self):
        self.register()
        for i in range(5):
            self.login(password="wrong-password-123", ip=f"198.51.100.{i + 1}")
        self.assertEqual(self.login(ip="198.51.100.99").status_code, 429)

    def test_ip_limit_stops_password_spraying(self):
        # one IP, many different accounts, 1-2 tries each: account limits never fire
        codes = [self.login(username=f"user{i:03d}", password="spray-attempt-1", ip="192.0.2.50").status_code
                 for i in range(21)]
        self.assertEqual(codes[:20], [401] * 20)
        self.assertEqual(codes[20], 429)
        # a different client IP is not affected
        self.assertEqual(self.login(username="user000", password="x", ip="192.0.2.51").status_code, 401)

    def test_successful_login_resets_account_counter(self):
        self.register()
        self.fail(4)
        self.assertEqual(self.login().status_code, 200)
        self.assertEqual(self.fail(4), [401] * 4)  # fresh budget

    def test_username_case_cannot_bypass_lockout(self):
        self.register()
        for name in ("alice", "ALICE", "Alice", "aLiCe", "alice "):
            self.login(username=name, password="wrong-password-123")
        self.assertEqual(self.login().status_code, 429)


if __name__ == "__main__":
    unittest.main()
