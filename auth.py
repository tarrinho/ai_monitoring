# auth.py — password hashing + server-side sessions for the dashboard user model.
#
# No third-party crypto: passwords use hashlib.scrypt (memory-hard, stdlib) so the
# minimal Alpine image gains ZERO new dependencies. Sessions are server-side and
# in-memory (a monitor restart just asks users to log in again — like the rate-limit
# state); each session is revalidated against the DB on every request, so disabling
# or deleting a user takes effect immediately. Each session carries a CSRF token for
# the state-changing POST endpoints (login is exempt — it mints the session).
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time

import config
import db

# scrypt cost — N=2**14 (~16 MB, tens of ms per hash): strong for interactive login
# without stalling the event loop. Bump N for more resistance if hardware allows.
_N, _R, _P = 1 << 14, 8, 1
_DKLEN = 32
_VALID_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
_VALID_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
ROLES = ("admin", "viewer")


# ───────────────────────────── password hashing ──────────────────────────────
def hash_password(pw: str) -> str:
    """Return a self-describing scrypt hash: scrypt$N$r$p$salt_b64$hash_b64."""
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=_N, r=_R, p=_P,
                        dklen=_DKLEN, maxmem=0)
    b64 = lambda b: base64.b64encode(b).decode()          # noqa: E731
    return f"scrypt${_N}${_R}${_P}${b64(salt)}${b64(dk)}"


def verify_password(pw: str, stored: str) -> bool:
    """Constant-time verify against a stored scrypt hash. False on any parse error."""
    try:
        scheme, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.scrypt(pw.encode(), salt=salt, n=int(n), r=int(r), p=int(p),
                            dklen=len(expected), maxmem=0)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def valid_username(name: str) -> bool:
    return bool(name) and bool(_VALID_NAME.match(name))


def valid_email(email: str) -> bool:
    return bool(email) and len(email) <= 254 and bool(_VALID_EMAIL.match(email))


def password_error(pw: str) -> str | None:
    """None if the password meets policy, else a human-readable reason."""
    if not pw or len(pw) < 8:
        return "password must be at least 8 characters"
    if len(pw) > 256:
        return "password too long"
    return None


# ───────────────────────────── session store ─────────────────────────────────
# sid -> {"user", "role", "expiry", "csrf"}. In-memory: single-instance app; a
# restart just forces re-login (acceptable for a monitor, like the lockout state).
_sessions: dict[str, dict] = {}


def _sweep(now: float) -> None:
    # Always drop expired sessions (cheap dict pass). Then enforce a HARD ceiling:
    # if still above config.SESSION_MAX, evict the soonest-to-expire until under it,
    # so the in-memory store can't grow without bound even under many live logins.
    for sid in [s for s, v in _sessions.items() if v["expiry"] <= now]:
        _sessions.pop(sid, None)
    over = len(_sessions) - config.SESSION_MAX
    if over > 0:
        for sid, _v in sorted(_sessions.items(),
                              key=lambda kv: kv[1]["expiry"])[:over]:
            _sessions.pop(sid, None)


def session_new(user: str, role: str) -> tuple[str, str]:
    """Create a session; returns (session_id, csrf_token)."""
    now = time.time()
    _sweep(now)
    sid = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    _sessions[sid] = {"user": user, "role": role,
                      "expiry": now + config.SESSION_TTL_S, "csrf": csrf}
    return sid, csrf


def session_get(sid: str | None) -> dict | None:
    """Return the live session for sid, or None if missing/expired. Expired → dropped."""
    if not sid:
        return None
    s = _sessions.get(sid)
    if not s:
        return None
    if s["expiry"] <= time.time():
        _sessions.pop(sid, None)
        return None
    return s


def session_drop(sid: str | None) -> None:
    if sid:
        _sessions.pop(sid, None)


def sessions_drop_user(name: str) -> int:
    """Invalidate every session for a user (on disable/delete). Returns count."""
    gone = [sid for sid, v in _sessions.items() if v["user"] == name]
    for sid in gone:
        _sessions.pop(sid, None)
    return len(gone)


def sessions_drop_user_except(name: str, keep_sid: str | None) -> int:
    """Invalidate all of a user's sessions EXCEPT keep_sid — used after a self-service
    password change so other devices are logged out but the current one stays."""
    gone = [sid for sid, v in _sessions.items()
            if v["user"] == name and sid != keep_sid]
    for sid in gone:
        _sessions.pop(sid, None)
    return len(gone)


def session_count() -> int:
    return len(_sessions)


# ───────────────────────────── bootstrap admin ───────────────────────────────
def bootstrap_admin() -> str | None:
    """Create the first admin from MONITOR_ADMIN_USER/PASSWORD when the users table
    is empty. Returns the created username, or None if skipped. Idempotent: never
    overwrites an existing user or seeds once any user exists."""
    name, pw = config.ADMIN_USER, config.ADMIN_PASSWORD
    email = config.ADMIN_EMAIL or ""
    if not name or not pw:
        return None
    if db.user_count() > 0:       # already seeded / users exist — do nothing
        return None
    if not valid_username(name) or password_error(pw):
        return None
    if email and not valid_email(email):
        return None
    if db.user_create(name, email, hash_password(pw), "admin", time.time()):
        return name
    return None
