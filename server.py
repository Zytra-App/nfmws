#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NFI Admin Panel - Backend Server
Self-contained Python standard library HTTP server (no external dependencies).

- First-run admin account setup
- Roles: admin, manager, developer, employee, viewer
- Games / Apps with a pending-approval flow (developers submit -> admin/manager approve)
- Per-item version management, Projects, Orders
- Invoices (buy/sale) submitted by employees, approved by admin/manager, with notifications
- Chat: team room, free chat, channels (created by admin/manager), private DMs,
  tickets (owned by creator, visible to admin/manager), chat management (mod_chat),
  admin-only message deletion, yellow warnings in chat
- Colored alerts, notifications, search-engine noindex toggle
- Sessions (HttpOnly cookies) + PBKDF2-SHA256 salted password hashing
- JSON file persistence
"""

import hashlib
import hmac
import json
import os
import secrets
import shutil
import ssl
import subprocess
import time
import threading
import mimetypes
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "data.json")
SECRET_FILE = os.path.join(BASE_DIR, ".secret_key")
DATA_KEY_FILE = os.path.join(BASE_DIR, ".data_key")

SESSION_TTL = 60 * 60 * 8
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()

ROLES = {"admin": 5, "manager": 4, "supervisor": 3, "developer": 2, "employee": 1, "viewer": 0}
EDIT_ROLES = ["admin", "manager", "developer"]
MEDIA_EDIT_ROLES = ["admin", "manager", "supervisor", "developer"]
APPROVE_ROLES = ["admin", "manager"]
INVOICE_EDIT_ROLES = ["admin", "manager", "developer", "employee"]
PEOPLE_ROLES = ["admin", "manager", "supervisor"]
TEAM_ROLES = ["admin", "manager", "supervisor"]
DOC_ROLES = ["admin", "manager", "supervisor"]
ALERT_ROLES = ["admin", "manager", "developer"]

PERSON_KINDS = ("manager", "supervisor", "teammate", "customer", "partner")
PRESENCE_OPTIONS = ("present", "absent", "vacation", "leave", "other")


def load_secret():
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "r") as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(SECRET_FILE, "w") as f:
        f.write(key)
    return key


SECRET_KEY = load_secret()


# ---------------------------------------------------------------------------
# Password hashing (salted PBKDF2-SHA256)
# ---------------------------------------------------------------------------
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        (salt + "--" + SECRET_KEY).encode("utf-8"),
        120000,
    )
    return salt + "$" + digest.hex()


def verify_password(password, stored):
    if "$" not in stored:
        return False
    salt, _ = stored.split("$", 1)
    return hmac.compare_digest(hash_password(password, salt), stored)


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
def create_session(username):
    token = secrets.token_urlsafe(32)
    with SESSIONS_LOCK:
        SESSIONS[token] = {"user": username, "created": time.time()}
    return token


def get_session_user(token):
    if not token:
        return None
    with SESSIONS_LOCK:
        s = SESSIONS.get(token)
        if not s:
            return None
        if time.time() - s["created"] > SESSION_TTL:
            del SESSIONS[token]
            return None
        s["created"] = time.time()
        return s["user"]


def destroy_session(token):
    with SESSIONS_LOCK:
        SESSIONS.pop(token, None)


# ---------------------------------------------------------------------------
# Encryption at rest (AES-256-CTR + HMAC-SHA256, pure standard library)
#
# data.json is stored encrypted. The 32-byte master key lives in .data_key
# (created automatically). Verified against FIPS-197 / SP 800-38A vectors.
# ---------------------------------------------------------------------------
_aes_e = [0] * 256
_aes_l = [0] * 256
_aes_x = 1
for _i in range(255):
    _aes_e[_i] = _aes_x
    _aes_l[_aes_x] = _i
    _aes_x ^= (_aes_x << 1)
    if _aes_x & 0x100:
        _aes_x ^= 0x11B
_aes_e[255] = 1


def _gf_inv(a):
    return 0 if a == 0 else _aes_e[255 - _aes_l[a]]


def _rol8(b, n):
    return ((b << n) | (b >> (8 - n))) & 0xff


def _affine(b):
    return (b ^ _rol8(b, 1) ^ _rol8(b, 2) ^ _rol8(b, 3) ^ _rol8(b, 4) ^ 0x63) & 0xff


AES_SBOX = [_affine(_gf_inv(i)) for i in range(256)]
AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _aes_xt(a):
    return ((a << 1) & 0xff) ^ (0x1b if (a & 0x80) else 0)


def _aes_key_expand(key):
    nk = len(key) // 4
    nr = {16: 10, 24: 12, 32: 14}[len(key)]
    nb = 4
    w = [list(key[i * 4:(i + 1) * 4]) for i in range(nk)]
    for i in range(nk, nb * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [AES_SBOX[b] for b in t]
            t[0] ^= AES_RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [AES_SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return [[w[4 * r + (c // 4)][c % 4] for c in range(16)] for r in range(nr + 1)]


def _aes_encrypt_block(rk, block):
    nr = len(rk) - 1
    st = [block[i] ^ rk[0][i] for i in range(16)]
    for r in range(1, nr):
        st = [AES_SBOX[b] for b in st]
        st = [st[0], st[5], st[10], st[15],
              st[4], st[9], st[14], st[3],
              st[8], st[13], st[2], st[7],
              st[12], st[1], st[6], st[11]]
        for c in range(4):
            i0 = c * 4; i1 = i0 + 1; i2 = i0 + 2; i3 = i0 + 3
            a0, a1, a2, a3 = st[i0], st[i1], st[i2], st[i3]
            st[i0] = _aes_xt(a0) ^ _aes_xt(a1) ^ a1 ^ a2 ^ a3
            st[i1] = a0 ^ _aes_xt(a1) ^ _aes_xt(a2) ^ a2 ^ a3
            st[i2] = a0 ^ a1 ^ _aes_xt(a2) ^ _aes_xt(a3) ^ a3
            st[i3] = _aes_xt(a0) ^ a0 ^ a1 ^ a2 ^ _aes_xt(a3)
        st = [st[i] ^ rk[r][i] for i in range(16)]
    st = [AES_SBOX[b] for b in st]
    st = [st[0], st[5], st[10], st[15],
          st[4], st[9], st[14], st[3],
          st[8], st[13], st[2], st[7],
          st[12], st[1], st[6], st[11]]
    return bytes([st[i] ^ rk[nr][i] for i in range(16)])


def _ctr_crypt(data, key, iv):
    counter = int.from_bytes(iv, "big")
    rk = _aes_key_expand(key)
    out = bytearray()
    i = 0
    while i < len(data):
        block = _aes_encrypt_block(rk, counter.to_bytes(16, "big"))
        out += bytes(p ^ k for p, k in zip(data[i:i + 16], block))
        i += 16
        counter += 1
    return bytes(out)


def encrypt_bytes(raw, key):
    ekey = hmac.new(key, b"enc", hashlib.sha256).digest()
    mkey = hmac.new(key, b"mac", hashlib.sha256).digest()
    iv = os.urandom(16)
    ct = _ctr_crypt(raw, ekey, iv)
    mac = hmac.new(mkey, iv + ct, hashlib.sha256).hexdigest()
    return {"enc": 1, "v": 1, "iv": iv.hex(), "ct": ct.hex(), "mac": mac}


def decrypt_bytes(pkt, key):
    ekey = hmac.new(key, b"enc", hashlib.sha256).digest()
    mkey = hmac.new(key, b"mac", hashlib.sha256).digest()
    iv = bytes.fromhex(pkt["iv"])
    ct = bytes.fromhex(pkt["ct"])
    want = hmac.new(mkey, iv + ct, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, pkt.get("mac", "")):
        raise ValueError("data.json integrity check failed (tampered or wrong key)")
    return _ctr_crypt(ct, ekey, iv)


def load_or_create_data_key():
    if os.path.exists(DATA_KEY_FILE):
        try:
            with open(DATA_KEY_FILE, "r", encoding="utf-8") as f:
                k = f.read().strip()
            if len(k) == 64:
                return bytes.fromhex(k)
        except Exception:
            pass
    key = secrets.token_bytes(32)
    with open(DATA_KEY_FILE, "w", encoding="utf-8") as f:
        f.write(key.hex())
    try:
        os.chmod(DATA_KEY_FILE, 0o600)
    except Exception:
        pass
    return key


DATA_KEY = load_or_create_data_key()
DATA_LOCK = threading.Lock()
_DATA_CACHE = {"mtime": -1.0, "data": None}


# ---------------------------------------------------------------------------
# Login rate limiting (brute-force protection)
# ---------------------------------------------------------------------------
LOGIN_ATTEMPTS = {}
LOGIN_LOCK = threading.Lock()
LOGIN_MAX = 5
LOGIN_WINDOW = 600
POLL_TIMEOUT = float(os.environ.get("NFI_POLL_TIMEOUT", "18"))


def login_allowed(ip):
    now = time.time()
    with LOGIN_LOCK:
        rec = [t for t in LOGIN_ATTEMPTS.get(ip, []) if now - t < LOGIN_WINDOW]
        LOGIN_ATTEMPTS[ip] = rec
        return len(rec) < LOGIN_MAX


def login_failed(ip):
    with LOGIN_LOCK:
        LOGIN_ATTEMPTS.setdefault(ip, []).append(time.time())


def login_succeeded(ip):
    with LOGIN_LOCK:
        LOGIN_ATTEMPTS.pop(ip, None)


# ---------------------------------------------------------------------------
# Data persistence
# ---------------------------------------------------------------------------
DEFAULT_DATA = {
    "settings": {"site_name": "NFI Admin Panel", "currency": "$", "seo_noindex": False},
    "users": {},
    "games": [],
    "apps": [],
    "projects": [],
    "orders": [],
    "channels": [],
    "tickets": [],
    "invoices": [],
    "messages": [],
    "alerts": [],
    "warnings": [],
    "notifications": [],
    "teams": [],
    "people": [],
}


def _mtime(path):
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0.0


def load_data():
    with DATA_LOCK:
        if _DATA_CACHE["data"] is not None and _DATA_CACHE["mtime"] == _mtime(DATA_FILE):
            return _DATA_CACHE["data"]
        data = None
        if os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, "r", encoding="utf-8") as f:
                    raw = f.read().strip()
                parsed = json.loads(raw) if raw else None
                if isinstance(parsed, dict) and parsed.get("enc") == 1:
                    data = json.loads(decrypt_bytes(parsed, DATA_KEY))
                elif isinstance(parsed, dict):
                    data = parsed  # legacy plaintext: migrated on next save
            except Exception as exc:
                raise SystemExit(
                    "FATAL: cannot load data.json (%s).\n"
                    "The file is corrupted, tampered with, or the key (.data_key) does not match.\n"
                    "Restore your backup instead of deleting it." % (exc,)
                )
        if data is None:
            data = json.loads(json.dumps(DEFAULT_DATA))
        for key, default in DEFAULT_DATA.items():
            if key == "settings":
                data.setdefault("settings", DEFAULT_DATA["settings"])
                data["settings"].setdefault("currency", "$")
                data["settings"].setdefault("seo_noindex", False)
            else:
                data.setdefault(key, default)
        for key in ("games", "apps"):
            for item in data.get(key, []):
                item.setdefault("status", "approved")
                item.setdefault("versions", [])
        _DATA_CACHE["data"] = data
        _DATA_CACHE["mtime"] = _mtime(DATA_FILE)
        return data


def save_data(data):
    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
    payload = json.dumps(encrypt_bytes(raw, DATA_KEY), ensure_ascii=False)
    with DATA_LOCK:
        tmp = DATA_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(payload)
        os.replace(tmp, DATA_FILE)
        _DATA_CACHE["data"] = data
        _DATA_CACHE["mtime"] = _mtime(DATA_FILE)


def public_user(user):
    out = dict(user)
    out.pop("password_hash", None)
    return out


def user_card(username, user):
    return {"username": username, "name": (user.get("name") or username),
            "role": user.get("role", "viewer"), "banned": bool(user.get("banned")),
            "mod_chat": bool(user.get("mod_chat")), "can_warn": bool(user.get("can_warn")),
            "teams": list(user.get("teams", [])),
            "created": user.get("created")}


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------
STATIC_FILES = {
    "/": "index.html",
    "/index.html": "index.html",
    "/styles.css": "styles.css",
    "/app.js": "app.js",
}


def sys_stdout_log(msg):
    try:
        print(msg, flush=True)
    except Exception:
        pass


class Handler(BaseHTTPRequestHandler):
    server_version = "NFIAdmin/3.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys_stdout_log(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}")

    # -- low level helpers ----------------------------------------------------
    def _send(self, code, body, ctype="application/json; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, payload, headers=None):
        self._send(code, json.dumps(payload, ensure_ascii=False), headers=headers)

    def _error(self, code, message):
        self._json(code, {"error": message})

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return None

    def _cookie_token(self):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            part = part.strip()
            if part.startswith("session="):
                return part[len("session="):]
        return None

    def _session_cookie(self, token):
        return f"session={token}; HttpOnly; Path=/; Max-Age={SESSION_TTL}"

    # -- auth helpers -----------------------------------------------------------
    def _me(self):
        data = load_data()
        token = self._cookie_token()
        uname = get_session_user(token)
        if not uname:
            return None, None, data
        user = data["users"].get(uname)
        if not user or user.get("banned"):
            return None, None, data
        return uname, user, data

    def _require(self, roles):
        uname, user, data = self._me()
        if not user:
            self._error(401, "Not authenticated")
            return None, None, None
        if user["role"] not in roles:
            self._error(403, "Forbidden")
            return None, None, None
        return uname, user, data

    def _require_any(self):
        return self._require(list(ROLES.keys()))

    def _can_manage(self, actor_role, target_role=None, to_role=None):
        if target_role and target_role == "admin" and actor_role != "admin":
            return False
        if to_role and to_role == "admin" and actor_role != "admin":
            return False
        if to_role and ROLES.get(to_role, 0) > ROLES.get(actor_role, 0):
            return False
        if target_role and ROLES.get(target_role, 0) > ROLES.get(actor_role, 0):
            return False
        return True

    def is_approver(self, user):
        return user["role"] in APPROVE_ROLES

    def is_admin(self, user):
        return user["role"] == "admin"

    def _notify(self, data, to, text, kind="info"):
        if to == "__managers__":
            for u, rec in data["users"].items():
                if rec.get("role") in APPROVE_ROLES:
                    self._notify(data, u, text, kind)
            return
        data["notifications"].append({
            "id": secrets.token_hex(8), "to": to, "text": text, "kind": kind,
            "at": time.time(), "read": False,
        })
        if len(data["notifications"]) > 1200:
            data["notifications"] = data["notifications"][-1200:]

    # ---------------------------------------------------------------------------
    # Routing: GET
    # ---------------------------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path in STATIC_FILES:
            self._serve_static(STATIC_FILES[path])
            return

        if path == "/api/status":
            data = load_data()
            uname, user, _ = self._me()
            self._json(200, {
                "setup_required": not data["users"],
                "authenticated": bool(user),
                "user": user_card(uname, user) if user else None,
            })
            return

        uname, user, data = self._require_any()
        if not user:
            return

        if path == "/api/me":
            self._json(200, {"authenticated": True, **user_card(uname, user)})
            return

        if path == "/api/users":
            users = [user_card(u, rec) for u, rec in data["users"].items()]
            self._json(200, {"users": users})
            return

        if path == "/api/settings":
            self._json(200, {"settings": data["settings"]})
            return

        if path == "/api/games":
            items = self._visible_media(data, "games", user)
            self._json(200, {"games": items})
            return

        if path.startswith("/api/games/"):
            gid = path[len("/api/games/"):]
            item = self._find_media(data, "games", gid)
            if item is None or (item.get("status") == "pending" and not self.is_approver(user)):
                self._error(404, "Item not found")
                return
            self._json(200, {"game": item})
            return

        if path == "/api/apps":
            items = self._visible_media(data, "apps", user)
            self._json(200, {"apps": items})
            return

        if path.startswith("/api/apps/"):
            aid = path[len("/api/apps/"):]
            item = self._find_media(data, "apps", aid)
            if item is None or (item.get("status") == "pending" and not self.is_approver(user)):
                self._error(404, "Item not found")
                return
            self._json(200, {"app": item})
            return

        if path == "/api/projects":
            self._json(200, {"projects": data["projects"]})
            return

        if path == "/api/orders":
            self._json(200, {"orders": data["orders"]})
            return

        if path == "/api/invoices":
            invoices = data["invoices"]
            if not self.is_approver(user):
                invoices = [inv for inv in invoices if inv["created_by"] == uname]
            self._json(200, {"invoices": invoices})
            return

        if path == "/api/channels":
            self._json(200, {"channels": data["channels"]})
            return

        if path == "/api/tickets":
            if self.is_approver(user):
                tickets = data["tickets"]
            else:
                tickets = [t for t in data["tickets"] if t["owner"] == uname]
            self._json(200, {"tickets": tickets})
            return

        if path.startswith("/api/tickets/"):
            tid = path[len("/api/tickets/"):]
            ticket = next((t for t in data["tickets"] if t["id"] == tid), None)
            if ticket is None:
                self._error(404, "Ticket not found")
                return
            if ticket["owner"] != uname and not self.is_approver(user):
                self._error(403, "مالک تیکت یا مدیر باید باشد")
                return
            msgs = [m for m in data["messages"] if m.get("ticket_id") == tid]
            self._json(200, {"ticket": ticket, "messages": msgs})
            return

        if path == "/api/notifications":
            mine = [n for n in data["notifications"]
                    if n.get("to") == uname or (n.get("to") == "__managers__" and self.is_approver(user))]
            mine = sorted(mine, key=lambda n: n["at"], reverse=True)[:100]
            unread = sum(1 for n in mine if not n.get("read"))
            self._json(200, {"notifications": mine, "unread": unread})
            return

        if path == "/api/alerts":
            self._json(200, {"alerts": data["alerts"][-50:]})
            return

        if path == "/api/warnings":
            self._json(200, {"warnings": data["warnings"][-50:]})
            return

        if path == "/api/messages/team":
            msgs = [m for m in data["messages"] if m.get("type") == "team"]
            self._json(200, {"messages": msgs})
            return

        if path == "/api/messages/free":
            msgs = [m for m in data["messages"] if m.get("type") == "free"]
            self._json(200, {"messages": msgs})
            return

        if path.startswith("/api/messages/room/"):
            rid = path[len("/api/messages/room/"):]
            if not any(ch["id"] == rid for ch in data["channels"]):
                self._error(404, "Channel not found")
                return
            msgs = [m for m in data["messages"] if m.get("type") == "room" and m.get("room") == rid]
            self._json(200, {"messages": msgs})
            return

        if path.startswith("/api/messages/between/"):
            if not (self.is_admin(user) or user.get("mod_chat")):
                self._error(403, "دسترسی مدیریت چت لازم است")
                return
            parts = path[len("/api/messages/between/"):].split("/")
            if len(parts) != 2:
                self._error(400, "Bad request")
                return
            u1, u2 = parts
            msgs = [m for m in data["messages"]
                    if m.get("type") == "dm" and
                    ((m["from"] == u1 and m.get("to") == u2) or
                     (m["from"] == u2 and m.get("to") == u1))]
            self._json(200, {"messages": msgs, "user1": u1, "user2": u2})
            return

        if path.startswith("/api/messages/dm/"):
            other = path[len("/api/messages/dm/"):]
            if other not in data["users"]:
                self._error(404, "User not found")
                return
            thread = [m for m in data["messages"]
                      if m.get("type") == "dm" and
                      ((m["from"] == uname and m.get("to") == other) or
                       (m["from"] == other and m.get("to") == uname))]
            self._json(200, {"messages": thread, "user": user_card(other, data["users"][other])})
            return

        if path == "/api/chats-overview":
            if not (self.is_admin(user) or user.get("mod_chat")):
                self._error(403, "دسترسی مدیریت چت لازم است")
                return
            self._json(200, {"conversations": self._chats_overview(data)})
            return

        if path == "/api/people":
            if user["role"] not in PEOPLE_ROLES:
                self._error(403, "این اطلاعات فقط برای ادمین، مدیر و سرپرست قابل مشاهده است")
                return
            self._json(200, {"people": data["people"]})
            return

        if path.startswith("/api/people/"):
            if user["role"] not in PEOPLE_ROLES:
                self._error(403, "این اطلاعات فقط برای ادمین، مدیر و سرپرست قابل مشاهده است")
                return
            pid = path[len("/api/people/"):]
            person = next((p for p in data["people"] if p["id"] == pid), None)
            if person is None:
                self._error(404, "Person not found")
                return
            self._json(200, {"person": person})
            return

        if path == "/api/teams":
            self._json(200, {"teams": self._public_teams(data)})
            return

        if path.startswith("/api/teams/"):
            tid = path[len("/api/teams/"):]
            team = next((t for t in data["teams"] if t["id"] == tid), None)
            if team is None:
                self._error(404, "Team not found")
                return
            self._json(200, {"team": self._public_team(team, data)})
            return

        if path == "/api/chat/main":
            msgs = sorted([m for m in data["messages"]
                           if m.get("type") == "main"], key=lambda m: m.get("at", 0))
            self._json(200, {"messages": msgs})
            return

        if path.startswith("/api/chat/team/"):
            tid = path[len("/api/chat/team/"):]
            team = next((t for t in data["teams"] if t["id"] == tid), None)
            if team is None:
                self._error(404, "Team not found")
                return
            if not self._team_viewable(user, team, uname):
                self._error(403, "فقط اعضای تیم و مدیران به این چت دسترسی دارند")
                return
            msgs = sorted([m for m in data["messages"]
                           if m.get("type") == "teamchat" and m.get("team_id") == tid],
                          key=lambda m: m.get("at", 0))
            self._json(200, {"messages": msgs, "team": team.get("name", "")})
            return

        if path == "/api/chat/poll":
            self._chat_poll(uname, user, data, parsed.query)
            return

        if path == "/api/invoice-doc":
            self._invoice_doc(uname, user, data, parsed.query)
            return

        self._error(404, "Not found")

    # -- media helpers -----------------------------------------------------------
    def _visible_media(self, data, key, user):
        if self.is_approver(user):
            return data[key]
        return [x for x in data[key] if x.get("status") != "pending"]

    def _find_media(self, data, key, item_id):
        for item in data[key]:
            if item["id"] == item_id:
                return item
        return None

    def _media_payload(self, body):
        name = (body.get("name") or "").strip()
        version = (body.get("version") or "").strip()
        build_date = (body.get("build_date") or "").strip()
        budget = (body.get("budget") or "").strip()
        if not name:
            return None, "نام الزامی است"
        if not version:
            return None, "ورژن الزامی است"
        if not build_date:
            return None, "تاریخ ساخت الزامی است"
        if not budget:
            return None, "بودجه الزامی است"
        return {"name": name, "version": version, "build_date": build_date, "budget": budget}, None

    def _media_patch(self, body):
        patch = {}
        for field, label in (("name", "نام"), ("version", "ورژن"), ("build_date", "تاریخ ساخت"), ("budget", "بودجه")):
            if field in body:
                val = (body.get(field) or "").strip()
                if not val:
                    return None, label + " الزامی است"
                patch[field] = val
        return patch, None

    def _chats_overview(self, data):
        convs = []
        def kind_count(title, kind, match):
            msgs = [m for m in data["messages"] if match(m)]
            last_at = max([m.get("at", 0) for m in msgs] or [0])
            convs.append({"kind": kind, "title": title, "count": len(msgs), "last_at": last_at})
        kind_count("چت تیم", "team", lambda m: m.get("type") == "team")
        kind_count("چت آزاد", "free", lambda m: m.get("type") == "free")
        for ch in data["channels"]:
            kind_count(ch["name"], "room", lambda m, rid=ch["id"]: m.get("type") == "room" and m.get("room") == rid)
            convs[-1]["room"] = ch["id"]
        pairs = set()
        for m in data["messages"]:
            if m.get("type") == "dm":
                a, b = m.get("from"), m.get("to")
                pairs.add(tuple(sorted([a, b])))
        for a, b in pairs:
            convs.append({"kind": "dm", "user1": a, "user2": b,
                          "title": a + " ↔ " + b, "count": 0, "last_at": 0})
        for t in data["tickets"]:
            msgs = [m for m in data["messages"] if m.get("ticket_id") == t["id"]]
            last_at = max([m.get("at", 0) for m in msgs] or [t.get("created", 0)])
            convs.append({"kind": "ticket", "ticket": t["id"], "title": "تیکت: " + t["title"],
                          "status": t.get("status"), "count": len(msgs), "last_at": last_at})
        convs.sort(key=lambda c: c.get("last_at", 0), reverse=True)
        return convs

    # ---------------------------------------------------------------------------
    # Routing: POST
    # ---------------------------------------------------------------------------
    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/api/setup":
            self._setup()
            return

        if path == "/api/login":
            self._login()
            return

        if path == "/api/logout":
            destroy_session(self._cookie_token())
            self._send(200, "{}", headers={"Set-Cookie": "session=; HttpOnly; Path=/; Max-Age=0"})
            return

        data = load_data()
        if not data["users"]:
            self._error(403, "Setup required")
            return

        uname, user, data = self._require_any()
        if not user:
            return

        if path == "/api/change-password":
            self._change_password(uname, user, data)
            return

        if path == "/api/reset-password":
            self._reset_password(uname, user, data)
            return

        if path == "/api/users":
            self._create_user(uname, user, data)
            return

        if path == "/api/games":
            self._create_media(uname, user, data, "games")
            return

        if path == "/api/apps":
            self._create_media(uname, user, data, "apps")
            return

        if path.startswith("/api/games/") and path.endswith("/versions"):
            gid = path[len("/api/games/"):-len("/versions")]
            self._add_version(uname, user, data, "games", gid)
            return

        if path.startswith("/api/apps/") and path.endswith("/versions"):
            aid = path[len("/api/apps/"):-len("/versions")]
            self._add_version(uname, user, data, "apps", aid)
            return

        if path == "/api/projects":
            self._create_project(uname, user, data)
            return

        if path == "/api/orders":
            self._create_order(uname, user, data)
            return

        if path == "/api/invoices":
            self._create_invoice(uname, user, data)
            return

        if path == "/api/channels":
            self._create_channel(uname, user, data)
            return

        if path == "/api/tickets":
            self._create_ticket(uname, user, data)
            return

        if path.startswith("/api/tickets/") and path.endswith("/messages"):
            tid = path[len("/api/tickets/"):-len("/messages")]
            self._ticket_message(uname, user, data, tid)
            return

        if path == "/api/messages":
            self._post_message(uname, user, data)
            return

        if path == "/api/people":
            self._create_person(uname, user, data)
            return

        if path == "/api/teams":
            self._create_team(uname, user, data)
            return

        if path.startswith("/api/teams/") and path.endswith("/members"):
            tid = path[len("/api/teams/"):-len("/members")]
            self._team_add_member(uname, user, data, tid)
            return

        if path == "/api/chat/main":
            self._post_main_msg(uname, user, data)
            return

        if path.startswith("/api/chat/team/"):
            tid = path[len("/api/chat/team/"):]
            self._post_team_msg(uname, user, data, tid)
            return

        if path == "/api/alerts":
            self._post_alert(uname, user, data)
            return

        if path == "/api/warnings":
            self._post_warning(uname, user, data)
            return

        if path == "/api/notifications/read":
            self._mark_notifications_read(uname, user, data)
            return

        self._error(404, "Not found")

    # ---------------------------------------------------------------------------
    # Routing: PUT
    # ---------------------------------------------------------------------------
    def do_PUT(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        uname, user, data = self._require_any()
        if not user:
            return

        if path == "/api/settings":
            self._update_settings(uname, user, data)
            return

        if path.startswith("/api/users/"):
            self._update_user(uname, user, data, path[len("/api/users/"):])
            return

        if path.startswith("/api/games/"):
            self._update_media(uname, user, data, "games", path[len("/api/games/"):])
            return

        if path.startswith("/api/apps/"):
            self._update_media(uname, user, data, "apps", path[len("/api/apps/"):])
            return

        if path.startswith("/api/projects/"):
            self._update_project(uname, user, data, path[len("/api/projects/"):])
            return

        if path.startswith("/api/orders/"):
            self._update_order(uname, user, data, path[len("/api/orders/"):])
            return

        if path.startswith("/api/invoices/"):
            self._update_invoice(uname, user, data, path[len("/api/invoices/"):])
            return

        if path.startswith("/api/people/"):
            self._update_person(uname, user, data, path[len("/api/people/"):])
            return

        if path.startswith("/api/teams/"):
            self._update_team(uname, user, data, path[len("/api/teams/"):])
            return

        if path.startswith("/api/tickets/") and path.endswith("/status"):
            tid = path[len("/api/tickets/"):-len("/status")]
            self._ticket_status(uname, user, data, tid)
            return

        self._error(404, "Not found")

    # ---------------------------------------------------------------------------
    # Routing: DELETE
    # ---------------------------------------------------------------------------
    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        uname, user, data = self._require_any()
        if not user:
            return

        if path.startswith("/api/users/"):
            self._delete_user(uname, user, data, path[len("/api/users/"):])
            return

        if path.startswith("/api/games/"):
            rest = path[len("/api/games/"):]
            parts = rest.split("/")
            if len(parts) == 3 and parts[1] == "versions":
                self._delete_version(uname, user, data, "games", parts[0], parts[2])
            elif len(parts) == 2 and parts[1] == "versions":
                self._delete_media(uname, user, data, "games", parts[0])
            else:
                self._delete_media(uname, user, data, "games", rest)
            return

        if path.startswith("/api/apps/"):
            rest = path[len("/api/apps/"):]
            parts = rest.split("/")
            if len(parts) >= 2 and parts[1] == "versions":
                vid = parts[2] if len(parts) > 2 else None
                self._delete_version(uname, user, data, "apps", parts[0], vid)
            else:
                self._delete_media(uname, user, data, "apps", rest)
            return

        if path.startswith("/api/projects/"):
            self._delete_project(uname, user, data, path[len("/api/projects/"):])
            return

        if path.startswith("/api/orders/"):
            self._delete_order(uname, user, data, path[len("/api/orders/"):])
            return

        if path.startswith("/api/invoices/"):
            self._delete_invoice(uname, user, data, path[len("/api/invoices/"):])
            return

        if path.startswith("/api/tickets/"):
            self._delete_ticket(uname, user, data, path[len("/api/tickets/"):])
            return

        if path.startswith("/api/messages/"):
            self._delete_message(uname, user, data, path[len("/api/messages/"):])
            return

        if path.startswith("/api/people/"):
            self._delete_person(uname, user, data, path[len("/api/people/"):])
            return

        if path.startswith("/api/teams/"):
            rest = path[len("/api/teams/"):].split("/")
            if len(rest) == 3 and rest[1] == "members":
                self._team_remove_member(uname, user, data, rest[0], rest[2])
            else:
                self._delete_team(uname, user, data, rest[0])
            return

        self._error(404, "Not found")

    # ---------------------------------------------------------------------------
    # Auth endpoints
    # ---------------------------------------------------------------------------
    def _setup(self):
        data = load_data()
        if data["users"]:
            self._error(403, "Setup already done")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        username = (body.get("username") or "").strip()
        name = (body.get("name") or "").strip()
        password = body.get("password") or ""
        if not username or not name or len(password) < 6:
            self._error(400, "Username, name and a password of at least 6 characters are required")
            return
        if username in data["users"]:
            self._error(400, "Username already exists")
            return
        data["users"][username] = {
            "name": name,
            "password_hash": hash_password(password),
            "role": "admin",
            "banned": False,
            "mod_chat": True,
            "can_warn": True,
            "created": time.time(),
        }
        save_data(data)
        token = create_session(username)
        self._json(200, {"ok": True, "username": username},
                   headers={"Set-Cookie": self._session_cookie(token)})

    def _login(self):
        ip = self.client_address[0] if self.client_address else "?"
        if not login_allowed(ip):
            self._error(429, "تلاش‌های ناموفق زیاد بود؛ چند دقیقه صبر کنید")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        data = load_data()
        rec = data["users"].get(username)
        if not rec or rec.get("banned") or not verify_password(password, rec.get("password_hash", "")):
            login_failed(ip)
            time.sleep(0.3)
            self._error(401, "نام کاربری یا رمز عبور نادرست است")
            return
        login_succeeded(ip)
        token = create_session(username)
        self._json(200, {"ok": True, "user": user_card(username, rec)},
                   headers={"Set-Cookie": self._session_cookie(token)})

    def _change_password(self, uname, user, data):
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        current = body.get("current") or ""
        new = body.get("new") or ""
        if len(new) < 6:
            self._error(400, "رمز جدید باید حداقل ۶ کاراکتر باشد")
            return
        if not verify_password(current, data["users"][uname]["password_hash"]):
            self._error(400, "رمز فعلی اشتباه است")
            return
        data["users"][uname]["password_hash"] = hash_password(new)
        save_data(data)
        self._json(200, {"ok": True})

    def _reset_password(self, uname, user, data):
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        target = (body.get("username") or "").strip()
        new = body.get("new") or ""
        if target not in data["users"]:
            self._error(404, "User not found")
            return
        if len(new) < 6:
            self._error(400, "رمز جدید باید حداقل ۶ کاراکتر باشد")
            return
        t = data["users"][target]
        if not self._can_manage(user["role"], target_role=t["role"]):
            self._error(403, "شما اجازه تغییر رمز این کاربر را ندارید")
            return
        t["password_hash"] = hash_password(new)
        save_data(data)
        self._json(200, {"ok": True})

    # ---------------------------------------------------------------------------
    # Users
    # ---------------------------------------------------------------------------
    def _create_user(self, uname, user, data):
        if user["role"] not in EDIT_ROLES:
            self._error(403, "Forbidden")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        username = (body.get("username") or "").strip()
        name = (body.get("name") or "").strip()
        password = body.get("password") or ""
        role = (body.get("role") or "viewer").strip()
        if role not in ROLES:
            self._error(400, "Invalid role")
            return
        if not username or not name or len(password) < 6:
            self._error(400, "نام کاربری، نام و رمز حداقل ۶ کاراکتری الزامی است")
            return
        if username in data["users"]:
            self._error(400, "این نام کاربری قبلاً ثبت شده است")
            return
        if not self._can_manage(user["role"], to_role=role):
            self._error(403, "شما اجازه ساخت این نقش را ندارید")
            return
        data["users"][username] = {
            "name": name,
            "password_hash": hash_password(password),
            "role": role,
            "banned": False,
            "mod_chat": False,
            "can_warn": False,
            "created": time.time(),
        }
        if self.is_admin(user):
            data["users"][username]["mod_chat"] = bool(body.get("mod_chat"))
            data["users"][username]["can_warn"] = bool(body.get("can_warn"))
        save_data(data)
        self._json(200, {"ok": True, "user": user_card(username, data["users"][username])})

    def _update_user(self, uname, user, data, target):
        if target not in data["users"]:
            self._error(404, "User not found")
            return
        t = data["users"][target]
        if not self._can_manage(user["role"], target_role=t["role"]):
            self._error(403, "شما اجازه تغییر این کاربر را ندارید")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        if not self.is_admin(user) and ("mod_chat" in body or "can_warn" in body):
            self._error(403, "فقط ادمین می‌تواند مجوزها را تغییر دهد")
            return
        if "name" in body:
            nm = (body.get("name") or "").strip()
            if nm:
                t["name"] = nm
        if "role" in body:
            new_role = (body.get("role") or "").strip()
            if new_role in ROLES:
                if not self._can_manage(user["role"], target_role=t["role"], to_role=new_role):
                    self._error(403, "شما اجازه تغییر نقش را ندارید")
                    return
                t["role"] = new_role
        if "banned" in body:
            banned = bool(body.get("banned"))
            if t["role"] == "admin" and user["role"] != "admin":
                self._error(403, "فقط ادمین می‌تواند اکانت ادمین را بن کند")
                return
            if target == uname and banned:
                self._error(400, "امکان بن کردن خودتان وجود ندارد")
                return
            t["banned"] = banned
            if banned:
                with SESSIONS_LOCK:
                    for tok, s in list(SESSIONS.items()):
                        if s["user"] == target:
                            del SESSIONS[tok]
        if self.is_admin(user):
            if "mod_chat" in body:
                t["mod_chat"] = bool(body.get("mod_chat"))
            if "can_warn" in body:
                t["can_warn"] = bool(body.get("can_warn"))
        save_data(data)
        self._json(200, {"ok": True, "user": user_card(target, data["users"][target])})

    def _delete_user(self, uname, user, data, target):
        if target not in data["users"]:
            self._error(404, "User not found")
            return
        if target == uname:
            self._error(400, "امکان حذف حساب خودتان وجود ندارد")
            return
        t = data["users"][target]
        if not self._can_manage(user["role"], target_role=t["role"]):
            self._error(403, "شما اجازه حذف این کاربر را ندارید")
            return
        del data["users"][target]
        with SESSIONS_LOCK:
            for tok, s in list(SESSIONS.items()):
                if s["user"] == target:
                    del SESSIONS[tok]
        save_data(data)
        self._json(200, {"ok": True})

    # ---------------------------------------------------------------------------
    # Games / Apps
    # ---------------------------------------------------------------------------
    def _create_media(self, uname, user, data, key):
        if user["role"] not in MEDIA_EDIT_ROLES:
            self._error(403, "دسترسی لازم را ندارید")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        item, err = self._media_payload(body)
        if err:
            self._error(400, err)
            return
        item["id"] = secrets.token_hex(8)
        item["versions"] = []
        item["status"] = "approved" if self.is_approver(user) else "pending"
        item["created_by"] = uname
        item["created_at"] = time.time()
        data[key].append(item)
        save_data(data)
        self._json(200, {"ok": True, "item": item})

    def _update_media(self, uname, user, data, key, item_id):
        if user["role"] not in MEDIA_EDIT_ROLES:
            self._error(403, "دسترسی لازم را ندارید")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        if "status" in body and not self.is_approver(user):
            self._error(403, "فقط ادمین یا مدیر می‌تواند وضعیت را تغییر دهد")
            return
        for item in data[key]:
            if item["id"] == item_id:
                if item.get("status") == "pending" and not self.is_approver(user):
                    self._error(403, "این مورد هنوز در انتظار تایید است")
                    return
                patch, err = self._media_patch(body)
                if err:
                    self._error(400, err)
                    return
                if "status" in body:
                    st = (body.get("status") or "").strip()
                    if st not in ("pending", "approved"):
                        self._error(400, "وضعیت معتبر نیست")
                        return
                    item["status"] = st
                elif patch:
                    item.update(patch)
                else:
                    self._error(400, "بدون تغییری ارسال نشده است")
                    return
                item["updated_at"] = time.time()
                save_data(data)
                self._json(200, {"ok": True, "item": item})
                return
        self._error(404, "Item not found")

    def _delete_media(self, uname, user, data, key, item_id):
        if user["role"] not in MEDIA_EDIT_ROLES:
            self._error(403, "دسترسی لازم را ندارید")
            return
        for item in data[key]:
            if item["id"] == item_id:
                if item.get("status") == "pending" and not self.is_approver(user):
                    self._error(403, "فقط ادمین یا مدیر می‌تواند مورد در انتظار را حذف کند")
                    return
                data[key] = [x for x in data[key] if x["id"] != item_id]
                save_data(data)
                self._json(200, {"ok": True})
                return
        self._error(404, "Item not found")

    def _add_version(self, uname, user, data, key, item_id):
        if user["role"] not in MEDIA_EDIT_ROLES:
            self._error(403, "دسترسی لازم را ندارید")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        version = (body.get("version") or "").strip()
        build_date = (body.get("build_date") or "").strip()
        notes = (body.get("notes") or "").strip()
        if not version or not build_date:
            self._error(400, "ورژن و تاریخ ساخت الزامی است")
            return
        for item in data[key]:
            if item["id"] == item_id:
                if item.get("status") == "pending" and not self.is_approver(user):
                    self._error(403, "این مورد هنوز در انتظار تایید است")
                    return
                item.setdefault("versions", [])
                item["versions"].append({
                    "id": secrets.token_hex(8),
                    "version": version,
                    "build_date": build_date,
                    "notes": notes,
                    "created_by": uname,
                    "created_at": time.time(),
                })
                item["version"] = version
                item["build_date"] = build_date
                item["updated_at"] = time.time()
                save_data(data)
                self._json(200, {"ok": True, "item": item})
                return
        self._error(404, "Item not found")

    def _delete_version(self, uname, user, data, key, item_id, version_id):
        if user["role"] not in MEDIA_EDIT_ROLES:
            self._error(403, "دسترسی لازم را ندارید")
            return
        for item in data[key]:
            if item["id"] == item_id:
                if item.get("status") == "pending" and not self.is_approver(user):
                    self._error(403, "این مورد هنوز در انتظار تایید است")
                    return
                before = len(item.get("versions", []))
                item["versions"] = [v for v in item.get("versions", []) if v["id"] != version_id]
                if len(item["versions"]) == before:
                    self._error(404, "Version not found")
                    return
                if item.get("versions"):
                    last = item["versions"][-1]
                    item["version"] = last["version"]
                    item["build_date"] = last["build_date"]
                save_data(data)
                self._json(200, {"ok": True, "item": item})
                return
        self._error(404, "Item not found")

    # ---------------------------------------------------------------------------
    # Projects
    # ---------------------------------------------------------------------------
    def _project_payload(self, body):
        name = (body.get("name") or "").strip()
        budget = (body.get("budget") or "").strip()
        status = (body.get("status") or "").strip()
        start_date = (body.get("start_date") or "").strip()
        if not name or not budget or not status or not start_date:
            return None, "همه فیلدها (نام، بودجه، وضعیت، تاریخ شروع) الزامی است"
        return {"name": name, "budget": budget, "status": status, "start_date": start_date}, None

    def _create_project(self, uname, user, data):
        if user["role"] not in EDIT_ROLES:
            self._error(403, "دسترسی لازم را ندارید")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        pr, err = self._project_payload(body)
        if err:
            self._error(400, err)
            return
        pr["id"] = secrets.token_hex(8)
        pr["created_by"] = uname
        pr["created_at"] = time.time()
        data["projects"].append(pr)
        save_data(data)
        self._json(200, {"ok": True, "item": pr})

    def _update_project(self, uname, user, data, pid):
        if user["role"] not in EDIT_ROLES:
            self._error(403, "دسترسی لازم را ندارید")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        for pr in data["projects"]:
            if pr["id"] == pid:
                patch, err = self._project_payload(body)
                if err:
                    self._error(400, err)
                    return
                pr.update(patch)
                pr["updated_at"] = time.time()
                save_data(data)
                self._json(200, {"ok": True, "item": pr})
                return
        self._error(404, "Project not found")

    def _delete_project(self, uname, user, data, pid):
        if user["role"] not in EDIT_ROLES:
            self._error(403, "دسترسی لازم را ندارید")
            return
        before = len(data["projects"])
        data["projects"] = [p for p in data["projects"] if p["id"] != pid]
        if len(data["projects"]) == before:
            self._error(404, "Project not found")
            return
        save_data(data)
        self._json(200, {"ok": True})

    # ---------------------------------------------------------------------------
    # Orders
    # ---------------------------------------------------------------------------
    ORDER_TYPES = ("site", "program", "game", "repair", "other")

    def _order_payload(self, body):
        name = (body.get("name") or "").strip()
        otype = (body.get("type") or "").strip()
        main_cost = (body.get("main_cost") or "").strip()
        build_cost = (body.get("build_cost") or "").strip()
        gross_profit = (body.get("gross_profit") or "").strip()
        net_profit = (body.get("net_profit") or "").strip()
        if not name:
            return None, "نام سفارش الزامی است"
        if otype not in self.ORDER_TYPES:
            return None, "نوع سفارش نامعتبر است"
        if not main_cost or not build_cost or not gross_profit or not net_profit:
            return None, "همه مقادیر هزینه و سود الزامی است"
        return {"name": name, "type": otype, "main_cost": main_cost, "build_cost": build_cost,
                "gross_profit": gross_profit, "net_profit": net_profit}, None

    def _create_order(self, uname, user, data):
        if user["role"] not in EDIT_ROLES:
            self._error(403, "دسترسی لازم را ندارید")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        order, err = self._order_payload(body)
        if err:
            self._error(400, err)
            return
        order["id"] = secrets.token_hex(8)
        order["created_by"] = uname
        order["created_at"] = time.time()
        data["orders"].append(order)
        save_data(data)
        self._json(200, {"ok": True, "item": order})

    def _update_order(self, uname, user, data, oid):
        if user["role"] not in EDIT_ROLES:
            self._error(403, "دسترسی لازم را ندارید")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        for o in data["orders"]:
            if o["id"] == oid:
                patch, err = self._order_payload(body)
                if err:
                    self._error(400, err)
                    return
                o.update(patch)
                o["updated_at"] = time.time()
                save_data(data)
                self._json(200, {"ok": True, "item": o})
                return
        self._error(404, "Order not found")

    def _delete_order(self, uname, user, data, oid):
        if user["role"] not in EDIT_ROLES:
            self._error(403, "دسترسی لازم را ندارید")
            return
        before = len(data["orders"])
        data["orders"] = [o for o in data["orders"] if o["id"] != oid]
        if len(data["orders"]) == before:
            self._error(404, "Order not found")
            return
        save_data(data)
        self._json(200, {"ok": True})

    # ---------------------------------------------------------------------------
    # Invoices
    # ---------------------------------------------------------------------------
    INVOICE_TYPES = ("sale", "buy")

    def _invoice_payload(self, body):
        inv_type = (body.get("inv_type") or "").strip()
        item_name = (body.get("item_name") or "").strip()
        try:
            quantity = float(body.get("quantity"))
            unit_price = float(body.get("unit_price"))
        except (TypeError, ValueError):
            return None, "مقدار واحد و قیمت واحد باید عدد باشند"
        if inv_type not in self.INVOICE_TYPES:
            return None, "نوع فاکتور معتبر نیست"
        if not item_name:
            return None, "نام کالا یا نرم‌افزار الزامی است"
        if quantity <= 0 or unit_price <= 0:
            return None, "تعداد و قیمت باید بیشتر از صفر باشند"
        return {"inv_type": inv_type, "item_name": item_name,
                "quantity": quantity, "unit_price": unit_price,
                "total": round(quantity * unit_price, 2)}, None

    def _create_invoice(self, uname, user, data):
        if user["role"] not in INVOICE_EDIT_ROLES:
            self._error(403, "فقط مدیر، دولپر یا کارمند می‌تواند فاکتور ثبت کند")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        inv, err = self._invoice_payload(body)
        if err:
            self._error(400, err)
            return
        inv["id"] = secrets.token_hex(8)
        inv["status"] = "pending"
        inv["created_by"] = uname
        inv["created_by_name"] = user.get("name") or uname
        inv["created_at"] = time.time()
        if not self.is_approver(user):
            self._notify(data, "__managers__",
                         f"فاکتور «{inv['item_name']}» ثبت شد و در انتظار تایید شماست", "invoice")
        data["invoices"].append(inv)
        save_data(data)
        self._json(200, {"ok": True, "item": inv})

    def _update_invoice(self, uname, user, data, iid):
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        for inv in data["invoices"]:
            if inv["id"] == iid:
                # approval / rejection
                if "status" in body:
                    if not self.is_approver(user):
                        self._error(403, "فقط ادمین یا مدیر می‌تواند تصمیم بگیرد")
                        return
                    st = (body.get("status") or "").strip()
                    if st in ("approved", "rejected"):
                        inv["status"] = st
                        inv["decided_by"] = uname
                        inv["decided_at"] = time.time()
                        label = "تایید شد" if st == "approved" else "رد شد"
                        self._notify(data, inv["created_by"],
                                     f"فاکتور «{inv['item_name']}» {label}", "invoice")
                        save_data(data)
                        self._json(200, {"ok": True, "item": inv})
                        return
                    self._error(400, "وضعیت معتبر نیست")
                    return
                # field editing
                if inv["status"] != "pending":
                    self._error(400, "فقط فاکتور در انتظار قابل ویرایش است")
                    return
                if not self.is_approver(user) and inv["created_by"] != uname:
                    self._error(403, "فقط ثبت‌کننده یا مدیر می‌تواند ویرایش کند")
                    return
                patch, err = self._invoice_payload(body)
                if err:
                    self._error(400, err)
                    return
                inv.update(patch)
                inv["updated_at"] = time.time()
                save_data(data)
                self._json(200, {"ok": True, "item": inv})
                return
        self._error(404, "Invoice not found")

    def _delete_invoice(self, uname, user, data, iid):
        for inv in data["invoices"]:
            if inv["id"] == iid:
                if not self.is_admin(user) and inv["created_by"] != uname:
                    self._error(403, "فقط ادمین یا ثبت‌کننده می‌تواند حذف کند")
                    return
                if inv["created_by"] == uname and not self.is_admin(user) and inv["status"] != "pending":
                    self._error(400, "فقط فاکتور در انتظار توسط ثبت‌کننده قابل حذف است")
                    return
                data["invoices"] = [x for x in data["invoices"] if x["id"] != iid]
                save_data(data)
                self._json(200, {"ok": True})
                return
        self._error(404, "Invoice not found")

    # ---------------------------------------------------------------------------
    # Channels / Tickets
    # ---------------------------------------------------------------------------
    def _create_channel(self, uname, user, data):
        if user["role"] not in APPROVE_ROLES:
            self._error(403, "فقط ادمین یا مدیر می‌تواند چت بسازد")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        name = (body.get("name") or "").strip()
        if not name:
            self._error(400, "نام چت الزامی است")
            return
        data["channels"].append({"id": secrets.token_hex(8), "name": name,
                                 "created_by": uname, "created_at": time.time()})
        save_data(data)
        self._json(200, {"ok": True, "channels": data["channels"]})

    def _create_ticket(self, uname, user, data):
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        title = (body.get("title") or "").strip()
        text = (body.get("text") or "").strip()
        if not title or not text:
            self._error(400, "عنوان و متن تیکت الزامی است")
            return
        t = {"id": secrets.token_hex(8), "title": title, "owner": uname,
             "owner_name": user.get("name") or uname, "status": "open",
             "created": time.time(), "updated": time.time()}
        data["tickets"].append(t)
        data["messages"].append({
            "id": secrets.token_hex(8), "type": "ticket", "ticket_id": t["id"],
            "from": uname, "from_name": user.get("name") or uname,
            "text": text, "at": time.time(),
        })
        save_data(data)
        self._json(200, {"ok": True, "ticket": t})

    def _ticket_message(self, uname, user, data, tid):
        ticket = next((t for t in data["tickets"] if t["id"] == tid), None)
        if ticket is None:
            self._error(404, "Ticket not found")
            return
        if ticket["owner"] != uname and not self.is_approver(user):
            self._error(403, "فقط مالک یا مدیر می‌تواند پاسخ دهد")
            return
        if ticket.get("status") == "done":
            self._error(400, "این تیکت اتمام شده و فقط قابل مشاهده است")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        text = (body.get("text") or "").strip()
        if not text:
            self._error(400, "متن پیام الزامی است")
            return
        data["messages"].append({
            "id": secrets.token_hex(8), "type": "ticket", "ticket_id": tid,
            "from": uname, "from_name": user.get("name") or uname,
            "text": text, "at": time.time(),
        })
        ticket["updated"] = time.time()
        save_data(data)
        self._json(200, {"ok": True})

    def _ticket_status(self, uname, user, data, tid):
        ticket = next((t for t in data["tickets"] if t["id"] == tid), None)
        if ticket is None:
            self._error(404, "Ticket not found")
            return
        if not self.is_approver(user):
            self._error(403, "فقط ادمین یا مدیر می‌تواند تیکت را اتمام کند")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        done = bool(body.get("done"))
        ticket["status"] = "done" if done else "open"
        ticket["updated"] = time.time()
        save_data(data)
        self._json(200, {"ok": True, "ticket": ticket})

    def _delete_ticket(self, uname, user, data, tid):
        if not self.is_admin(user):
            self._error(403, "فقط ادمین می‌تواند تیکت را حذف کند")
            return
        if not any(t["id"] == tid for t in data["tickets"]):
            self._error(404, "Ticket not found")
            return
        data["tickets"] = [t for t in data["tickets"] if t["id"] != tid]
        data["messages"] = [m for m in data["messages"] if m.get("ticket_id") != tid]
        save_data(data)
        self._json(200, {"ok": True})

    # ---------------------------------------------------------------------------
    # Settings
    # ---------------------------------------------------------------------------
    def _update_settings(self, uname, user, data):
        if user["role"] not in EDIT_ROLES:
            self._error(403, "دسترسی لازم را ندارید")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        settings = data["settings"]
        if "site_name" in body:
            settings["site_name"] = (body.get("site_name") or "").strip() or "NFI Admin Panel"
        if "currency" in body:
            settings["currency"] = (body.get("currency") or "").strip() or "$"
        if "seo_noindex" in body:
            settings["seo_noindex"] = bool(body.get("seo_noindex"))
        save_data(data)
        self._json(200, {"ok": True, "settings": settings})

    # ---------------------------------------------------------------------------
    # Messaging / Alerts / Warnings
    # ---------------------------------------------------------------------------
    def _post_message(self, uname, user, data):
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        text = (body.get("text") or "").strip()
        if not text:
            self._error(400, "متن پیام الزامی است")
            return
        msg = {
            "id": secrets.token_hex(8),
            "from": uname,
            "from_name": user.get("name"),
            "text": text,
            "at": time.time(),
        }
        room = (body.get("room") or "").strip()
        if room in ("team", "free"):
            msg["type"] = room
        elif room == "dm" or body.get("to"):
            target = (body.get("to") or "").strip()
            if target not in data["users"]:
                self._error(404, "User not found")
                return
            if target == uname:
                self._error(400, "امکان ارسال پیام به خودتان وجود ندارد")
                return
            msg["to"] = target
            msg["type"] = "dm"
        elif room:
            if not any(ch["id"] == room for ch in data["channels"]):
                self._error(404, "Channel not found")
                return
            msg["room"] = room
            msg["type"] = "room"
        else:
            msg["type"] = "team"
        data["messages"].append(msg)
        if len(data["messages"]) > 5000:
            data["messages"] = data["messages"][-5000:]
        save_data(data)
        self._json(200, {"ok": True, "message": msg})

    def _delete_message(self, uname, user, data, mid):
        if not self.is_admin(user):
            self._error(403, "فقط ادمین می‌تواند پیام را حذف کند")
            return
        for i, m in enumerate(data["messages"]):
            if m["id"] == mid:
                del data["messages"][i]
                save_data(data)
                self._json(200, {"ok": True})
                return
        self._error(404, "Message not found")

    def _post_alert(self, uname, user, data):
        if user["role"] not in ALERT_ROLES:
            self._error(403, "فقط مدیران و دولپرها می‌توانند الرت بفرستند")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        text = (body.get("text") or "").strip()
        color = (body.get("color") or "").strip() or "#2ed9a4"
        if not text:
            self._error(400, "متن الرت الزامی است")
            return
        data["alerts"].append({
            "id": secrets.token_hex(8), "from": uname, "from_name": user.get("name"),
            "text": text, "color": color, "at": time.time(),
        })
        if len(data["alerts"]) > 200:
            data["alerts"] = data["alerts"][-200:]
        save_data(data)
        self._json(200, {"ok": True})

    def _post_warning(self, uname, user, data):
        if not (self.is_admin(user) or user.get("can_warn")):
            self._error(403, "فقط ادمین یا افراد دارای مجوز می‌توانند اخطار بفرستند")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        text = (body.get("text") or "").strip()
        if not text:
            self._error(400, "متن اخطار الزامی است")
            return
        data["warnings"].append({
            "id": secrets.token_hex(8), "from": uname, "from_name": user.get("name"),
            "text": text, "at": time.time(),
        })
        if len(data["warnings"]) > 200:
            data["warnings"] = data["warnings"][-200:]
        save_data(data)
        self._json(200, {"ok": True})

    def _mark_notifications_read(self, uname, user, data):
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        if body.get("all"):
            for n in data["notifications"]:
                if n.get("to") == uname or (n.get("to") == "__managers__" and self.is_approver(user)):
                    n["read"] = True
        else:
            ids = set(body.get("ids") or [])
            for n in data["notifications"]:
                if n["id"] in ids and (n.get("to") == uname or n.get("to") == "__managers__"):
                    n["read"] = True
        save_data(data)
        self._json(200, {"ok": True})

    # ---------------------------------------------------------------------------
    # People records ("افراد تیم" - non-account directory)
    # ---------------------------------------------------------------------------
    @staticmethod
    def _calc_age(birth_date):
        try:
            bd = datetime.strptime(birth_date.strip(), "%Y-%m-%d")
        except Exception:
            return None, "تاریخ تولد باید به شکل YYYY-MM-DD باشد"
        today = datetime.now().date()
        age = today.year - bd.date().year - ((today.month, today.day) < (bd.date().month, bd.date().day))
        if age < 0 or age > 120:
            return None, "تاریخ تولد معتبر نیست"
        return age, None

    def _person_payload(self, body):
        full_first = (body.get("first_name") or body.get("name") or "").strip()
        last = (body.get("last_name") or "").strip()
        kind = (body.get("kind") or "teammate").strip()
        phone = (body.get("phone") or "").strip()
        company = (body.get("company") or "").strip()
        birth_date = (body.get("birth_date") or "").strip()
        job = (body.get("job") or "").strip()
        salary = (body.get("salary") or "").strip()
        presence = (body.get("presence") or "").strip()
        notes = (body.get("notes") or "").strip()
        photo = body.get("photo") or ""
        if not full_first:
            return None, "نام الزامی است"
        if not phone:
            return None, "شماره تماس الزامی است"
        if not company:
            return None, "نام شرکت / تیم / فروشگاه الزامی است"
        if kind not in PERSON_KINDS:
            return None, "نوع فرد معتبر نیست"
        if presence and presence not in PRESENCE_OPTIONS:
            return None, "وضعیت حضور معتبر نیست"
        age = None
        if birth_date:
            age, err = self._calc_age(birth_date)
            if err:
                return None, err
        if photo and not (isinstance(photo, str) and photo.startswith("data:image/")):
            photo = ""
        if photo and len(photo) > 700000:
            return None, "حجم تصویر بیش از حد مجاز است"
        return {
            "first_name": full_first, "last_name": last,
            "full_name": " ".join(x for x in (full_first, last) if x),
            "kind": kind, "phone": phone, "company": company,
            "birth_date": birth_date, "age": age, "birth_year": birth_date[:4] if birth_date else "",
            "job": job, "salary": salary, "presence": presence,
            "photo": photo or None, "notes": notes,
        }, None

    def _create_person(self, uname, user, data):
        if user["role"] not in PEOPLE_ROLES:
            self._error(403, "فقط ادمین، مدیر یا سرپرست می‌تواند فرد ثبت کند")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        rec, err = self._person_payload(body)
        if err:
            self._error(400, err)
            return
        rec["id"] = secrets.token_hex(8)
        rec["created_by"] = uname
        rec["created_at"] = time.time()
        rec["updated_at"] = rec["created_at"]
        data["people"].append(rec)
        save_data(data)
        self._json(200, {"ok": True, "person": rec})

    def _update_person(self, uname, user, data, pid):
        if user["role"] not in PEOPLE_ROLES:
            self._error(403, "فقط ادمین، مدیر یا سرپرست می‌تواند پرونده ویرایش کند")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        person = next((p for p in data["people"] if p["id"] == pid), None)
        if person is None:
            self._error(404, "Person not found")
            return
        new_vals, err = self._person_payload(body)
        if err:
            self._error(400, err)
            return
        person.update(new_vals)
        person["updated_at"] = time.time()
        save_data(data)
        self._json(200, {"ok": True, "person": person})

    def _delete_person(self, uname, user, data, pid):
        if user["role"] not in PEOPLE_ROLES:
            self._error(403, "فقط ادمین، مدیر یا سرپرست می‌تواند پرونده حذف کند")
            return
        person = next((p for p in data["people"] if p["id"] == pid), None)
        if person is None:
            self._error(404, "Person not found")
            return
        data["people"] = [p for p in data["people"] if p["id"] != pid]
        save_data(data)
        self._json(200, {"ok": True})

    # ---------------------------------------------------------------------------
    # Teams
    # ---------------------------------------------------------------------------
    def _public_team(self, team, data):
        members = []
        for u in team.get("members", []):
            rec = data["users"].get(u)
            if rec:
                members.append({"username": u, "name": rec.get("name") or u,
                                "role": rec.get("role", "viewer")})
        return {"id": team["id"], "name": team.get("name", ""),
                "description": team.get("description", ""),
                "members": members, "members_count": len(members),
                "created_by": team.get("created_by", ""), "created_at": team.get("created_at", 0)}

    def _public_teams(self, data):
        return [self._public_team(t, data) for t in data["teams"]]

    def _team_viewable(self, user, team, uname):
        if user["role"] in APPROVE_ROLES:
            return True
        return uname in team.get("members", [])

    def _find_team(self, data, tid):
        return next((t for t in data["teams"] if t["id"] == tid), None)

    def _create_team(self, uname, user, data):
        if user["role"] not in TEAM_ROLES:
            self._error(403, "فقط ادمین، مدیر یا سرپرست می‌تواند تیم بسازد")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        name = (body.get("name") or "").strip()
        desc = (body.get("description") or "").strip()
        if not name:
            self._error(400, "نام تیم الزامی است")
            return
        team = {"id": secrets.token_hex(8), "name": name, "description": desc,
                "members": [], "created_by": uname, "created_at": time.time()}
        data["teams"].append(team)
        save_data(data)
        self._json(200, {"ok": True, "team": self._public_team(team, data)})

    def _update_team(self, uname, user, data, tid):
        if user["role"] not in TEAM_ROLES:
            self._error(403, "فقط ادمین، مدیر یا سرپرست می‌تواند تیم ویرایش کند")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        team = self._find_team(data, tid)
        if team is None:
            self._error(404, "Team not found")
            return
        if "name" in body and body["name"].strip():
            team["name"] = body["name"].strip()
        if "description" in body:
            team["description"] = (body.get("description") or "").strip()
        save_data(data)
        self._json(200, {"ok": True, "team": self._public_team(team, data)})

    def _delete_team(self, uname, user, data, tid):
        if user["role"] not in TEAM_ROLES:
            self._error(403, "فقط ادمین، مدیر یا سرپرست می‌تواند تیم حذف کند")
            return
        team = self._find_team(data, tid)
        if team is None:
            self._error(404, "Team not found")
            return
        team_name = team.get("name", "")
        data["teams"] = [t for t in data["teams"] if t["id"] != tid]
        data["messages"] = [m for m in data["messages"]
                            if not (m.get("type") == "teamchat" and m.get("team_id") == tid)]
        save_data(data)
        self._json(200, {"ok": True, "name": team_name})

    def _team_add_member(self, uname, user, data, tid):
        if user["role"] not in TEAM_ROLES:
            self._error(403, "فقط ادمین، مدیر یا سرپرست می‌تواند عضو اضافه کند")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        team = self._find_team(data, tid)
        if team is None:
            self._error(404, "Team not found")
            return
        username = (body.get("username") or "").strip()
        if username not in data["users"]:
            self._error(404, "کاربر یافت نشد")
            return
        members = team.setdefault("members", [])
        if username in members:
            self._error(400, "این کاربر قبلاً عضو تیم است")
            return
        members.append(username)
        save_data(data)
        self._json(200, {"ok": True, "team": self._public_team(team, data)})

    def _team_remove_member(self, uname, user, data, tid, username):
        if user["role"] not in TEAM_ROLES:
            self._error(403, "فقط ادمین، مدیر یا سرپرست می‌تواند عضو حذف کند")
            return
        team = self._find_team(data, tid)
        if team is None:
            self._error(404, "Team not found")
            return
        members = team.setdefault("members", [])
        if username not in members:
            self._error(404, "این کاربر عضو تیم نیست")
            return
        members.remove(username)
        save_data(data)
        self._json(200, {"ok": True, "team": self._public_team(team, data)})

    # ---------------------------------------------------------------------------
    # New chat: main («چت اصلی») and team chats
    # ---------------------------------------------------------------------------
    def _post_main_msg(self, uname, user, data):
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        text = (body.get("text") or "").strip()
        if not text:
            self._error(400, "متن پیام الزامی است")
            return
        msg = {"id": secrets.token_hex(8), "type": "main", "from": uname,
               "from_name": user.get("name"), "text": text, "at": time.time()}
        data["messages"].append(msg)
        if len(data["messages"]) > 5000:
            data["messages"] = data["messages"][-5000:]
        save_data(data)
        self._json(200, {"ok": True, "message": msg})

    def _post_team_msg(self, uname, user, data, tid):
        team = self._find_team(data, tid)
        if team is None:
            self._error(404, "Team not found")
            return
        if not self._team_viewable(user, team, uname):
            self._error(403, "فقط اعضای تیم و مدیران به این چت دسترسی دارند")
            return
        body = self._read_body()
        if body is None:
            self._error(400, "Invalid request body")
            return
        text = (body.get("text") or "").strip()
        if not text:
            self._error(400, "متن پیام الزامی است")
            return
        msg = {"id": secrets.token_hex(8), "type": "teamchat", "team_id": tid,
               "from": uname, "from_name": user.get("name"), "text": text, "at": time.time()}
        data["messages"].append(msg)
        if len(data["messages"]) > 5000:
            data["messages"] = data["messages"][-5000:]
        save_data(data)
        self._json(200, {"ok": True, "message": msg})

    # ---------------------------------------------------------------------------
    # Long-polling chat (near real-time, no manual refresh)
    # ---------------------------------------------------------------------------
    def _chat_poll(self, uname, user, data, query):
        qs = parse_qs(query)
        scope = (qs.get("scope") or ["main"])[0].strip()
        try:
            after = float((qs.get("after") or ["0"])[0])
        except ValueError:
            after = 0.0
        tid = None
        if scope == "main":
            pass
        elif scope.startswith("team:"):
            tid = scope[5:]
            team = self._find_team(data, tid)
            if team is None:
                self._error(404, "Team not found")
                return
            if not self._team_viewable(user, team, uname):
                self._error(403, "فقط اعضای تیم و مدیران به این چت دسترسی دارند")
                return
        else:
            self._error(400, "scope should be 'main' or 'team:<id>'")
            return
        deadline = time.time() + POLL_TIMEOUT
        while True:
            d = load_data()
            if tid is None:
                msgs = [m for m in d["messages"] if m.get("type") == "main"]
            else:
                msgs = [m for m in d["messages"]
                        if m.get("type") == "teamchat" and m.get("team_id") == tid]
            fresh = [m for m in msgs if (m.get("at") or 0) > after]
            if fresh:
                fresh.sort(key=lambda m: m.get("at", 0))
                self._json(200, {"messages": fresh})
                return
            if time.time() >= deadline:
                self._json(200, {"messages": []})
                return
            time.sleep(0.6)

    # ---------------------------------------------------------------------------
    # سند فاکتور فروش (orders date-range report)
    # ---------------------------------------------------------------------------
    def _invoice_doc(self, uname, user, data, query):
        if user["role"] not in DOC_ROLES:
            self._error(403, "فقط ادمین، مدیر یا سرپرست به سند فاکتور دسترسی دارد")
            return
        qs = parse_qs(query)
        from_s = (qs.get("from") or [""])[0].strip()
        to_s = (qs.get("to") or [""])[0].strip()
        if not from_s or not to_s:
            self._error(400, "بازه تاریخ را انتخاب کنید")
            return
        try:
            f_ts = datetime.strptime(from_s, "%Y-%m-%d").timestamp()
            t_ts = (datetime.strptime(to_s, "%Y-%m-%d") + timedelta(days=1)).timestamp()
        except ValueError:
            self._error(400, "تاریخ نامعتبر است")
            return
        items = [o for o in data["orders"]
                 if f_ts <= o.get("created_at", 0) < t_ts]
        def s(v):
            try:
                return float(v or 0)
            except (TypeError, ValueError):
                return 0.0
        summary = {
            "count": len(items),
            "main_cost": sum(s(o.get("main_cost")) for o in items),
            "build_cost": sum(s(o.get("build_cost")) for o in items),
            "gross_profit": sum(s(o.get("gross_profit")) for o in items),
            "net_profit": sum(s(o.get("net_profit")) for o in items),
        }
        self._json(200, {"items": items, "summary": summary, "from": from_s, "to": to_s})

    # ---------------------------------------------------------------------------
    # Static + misc
    # ---------------------------------------------------------------------------
    def _serve_static(self, filename):
        filepath = os.path.join(BASE_DIR, filename)
        if not os.path.exists(filepath):
            self._error(404, "Not found")
            return
        ctype = mimetypes.guess_type(filepath)[0] or "application/octet-stream"
        with open(filepath, "rb") as f:
            content = f.read()
        headers = {}
        if filename in ("index.html", "app.js", "styles.css"):
            headers["Cache-Control"] = "no-store"
            try:
                data = load_data()
                if data["settings"].get("seo_noindex"):
                    text = content.decode("utf-8")
                    if 'name="robots"' not in text:
                        text = text.replace("</head>", '\n  <meta name="robots" content="noindex, nofollow">\n</head>', 1)
                    content = text.encode("utf-8")
                    headers["X-Robots-Tag"] = "noindex, nofollow"
            except Exception:
                pass
        self._send(200, content, ctype=ctype + ("; charset=utf-8" if ctype.startswith("text/") else ""),
                   headers=headers)

    def send_header(self, keyword, value):
        if keyword.lower() == "connection" and value == "keep-alive":
            value = "close"
        super().send_header(keyword, value)


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------
def _autogen_cert(cert, key):
    exe = shutil.which("openssl")
    if not exe:
        print("NFI_TLS=1 but openssl was not found and no cert.pem/key.pem exists; staying on HTTP.")
        return None, None
    try:
        subprocess.run([exe, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "3650", "-subj", "/CN=localhost",
                        "-keyout", key, "-out", cert],
                       check=True, capture_output=True)
        print("Generated self-signed TLS certificate:", cert)
        return cert, key
    except Exception as exc:
        print("TLS certificate generation failed:", exc)
        return None, None


def main():
    data = load_data()
    if not os.path.exists(DATA_FILE):
        save_data(data)

    port = int(os.environ.get("PORT", "8000"))
    host = "0.0.0.0"
    server = ThreadingHTTPServer((host, port), Handler)

    cert = os.environ.get("NFI_CERT") or os.path.join(BASE_DIR, "cert.pem")
    key = os.environ.get("NFI_KEY") or os.path.join(BASE_DIR, "key.pem")
    if not (os.path.exists(cert) and os.path.exists(key)) and os.environ.get("NFI_TLS") == "1":
        cert, key = _autogen_cert(cert, key)
    if cert and key and os.path.exists(cert) and os.path.exists(key):
        tls = True
    else:
        tls = False
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)

    scheme = "https" if tls else "http"
    note = "" if data["users"] else "  (BETA - setup the first admin account)"
    print(f"NFI Admin Panel running at {scheme}://localhost:{port}{note}")
    if not tls:
        print("Tip: put cert.pem/key.pem here (or set NFI_TLS=1) to enable HTTPS.")
    print("Data is encrypted at rest in data.json (.data_key must be backed up too).")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()