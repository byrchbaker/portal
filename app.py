import os
import ssl
import json
import time
import secrets
import threading
import binascii
import hashlib
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import quote, quote_plus

from flask import (
    Flask, render_template, request, redirect, url_for, flash, make_response,
    abort, current_app, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import requests
from urllib3.exceptions import InsecureRequestWarning

from sqlalchemy import event, func
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError, OperationalError
import sqlite3

from utils import apply_uptime_scoring
from models import (
    db, User, Announcement, WebSubmission, WebChallenge, Inject, Team,
    Service, ServiceStatus, VMImage, ImageScoreEvent
)

# ---------------------------------------------------------------------------
# Optional deps for the websocket console proxy.
#   pip install flask-sock websocket-client
# The app still boots without them; the console route just reports why.
# ---------------------------------------------------------------------------
try:
    from flask_sock import Sock
    _HAS_FLASK_SOCK = True
except Exception:
    _HAS_FLASK_SOCK = False

try:
    import websocket as wsclient  # websocket-client
    _HAS_WS_CLIENT = True
except Exception:
    _HAS_WS_CLIENT = False


# ---------------------------------------------------------------------------
# Crypto helpers for the scoring engine transport (unchanged)
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_AESGCM = True
except Exception:
    _HAS_AESGCM = False
    try:
        from Crypto.Cipher import AES  # type: ignore
        _HAS_PYCRYPTO = True
    except Exception:
        _HAS_PYCRYPTO = False


# Use non-ASCII bytes as a delimiter to match the Go client.
DELIM = "\xff\xde"

ENGINE_SHARED_KEY = os.environ.get('ENGINE_SHARED_KEY', 'changeme-please').strip()


def _aesgcm_decrypt_from_hex(hex_payload: str, password: str) -> str:
    """
    Decrypts hex(encryptString(password, plaintext)) produced by the Go engine.
    - encryptString: AES-GCM with 12-byte nonce, key = sha256(password)
    - ciphertext bytes = nonce[12] || gcm(ciphertext || tag)
    """
    if not hex_payload:
        raise ValueError("empty AES-GCM payload")
    try:
        raw = binascii.unhexlify(hex_payload.strip())
    except Exception as e:
        raise ValueError(f"invalid hex: {e}")

    if len(raw) < 13:
        raise ValueError("ciphertext too short for AES-GCM")

    nonce = raw[:12]
    ct_and_tag = raw[12:]
    key = hashlib.sha256((password or "").encode("utf-8")).digest()

    if _HAS_AESGCM:
        try:
            pt = AESGCM(key).decrypt(nonce, ct_and_tag, associated_data=None)
            return pt.decode("utf-8", errors="ignore")
        except Exception as e:
            raise ValueError(f"AES-GCM decrypt Missed: {e}")

    if '_HAS_PYCRYPTO' in globals() and _HAS_PYCRYPTO:
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            if len(ct_and_tag) < 17:
                raise ValueError("ciphertext missing GCM tag")
            ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
            pt = cipher.decrypt_and_verify(ct, tag)
            return pt.decode("utf-8", errors="ignore")
        except Exception as e:
            raise ValueError(f"AES-GCM (PyCryptodome) decrypt Missed: {e}")

    raise ValueError("No AES-GCM backend available (install 'cryptography' or 'pycryptodome').")


def _hex_to_bytes(s: str) -> bytes:
    try:
        return binascii.unhexlify((s or "").strip())
    except Exception:
        return b""


def _xor_crypt(data: bytes, key: str) -> bytes:
    """Simple XOR stream with repeating key (matches many CCDC engines)."""
    if not key:
        return data
    kb = key.encode("utf-8")
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ kb[i % len(kb)]
    return bytes(out)


def _looks_like_update(txt: str) -> bool:
    return (DELIM in txt) and ("team" in txt) and ("image" in txt) and ("score" in txt)


def _parse_kv_delim(s: str) -> dict:
    """Parse "key<DELIM>value<DELIM>..." emitted by writeString() in the Go client."""
    parts = s.split(DELIM)
    out = {}
    for i in range(0, len(parts) - 1, 2):
        k = (parts[i] or "").strip()
        v = parts[i + 1]
        if k:
            out[k] = v
    return out


def _decrypt_outer(hex_payload: str, key: str) -> tuple:
    """
    Decrypt the outer 'update' blob. Returns (plaintext, used_encryption_bool).
    """
    raw = _hex_to_bytes(hex_payload)
    if not raw:
        raise ValueError("Update payload is not valid hex or empty")

    # 1) plaintext (DisableRemoteEncryption=true)
    try:
        txt_plain = raw.decode("utf-8", errors="ignore")
        if _looks_like_update(txt_plain):
            return txt_plain, False
    except Exception:
        pass

    # 2) AES-GCM with shared key
    try:
        txt = _aesgcm_decrypt_from_hex(hex_payload, key)
        if _looks_like_update(txt):
            return txt, True
    except Exception:
        pass

    # 3) legacy XOR fallback
    dec = _xor_crypt(raw, key)
    try:
        txt = dec.decode("utf-8", errors="ignore")
    except Exception:
        txt = ""
    if _looks_like_update(txt):
        return txt, True

    raise ValueError("Could not decrypt update with shared key")


def _decrypt_inner_vulns(vulns_hex: str, key: str) -> str:
    if not vulns_hex:
        return ""
    try:
        return _aesgcm_decrypt_from_hex(vulns_hex, key)
    except Exception:
        vb = _hex_to_bytes(vulns_hex)
        if not vb:
            return ""
        dec = _xor_crypt(vb, key) if key else vb
        try:
            return dec.decode("utf-8", errors="ignore")
        except Exception:
            return ""


def _current_image_total(team_id: int, image_id: int) -> int:
    cur = db.session.query(func.coalesce(func.sum(ImageScoreEvent.delta), 0)) \
        .filter(ImageScoreEvent.team_id == team_id,
                ImageScoreEvent.image_id == image_id).scalar()
    return int(cur or 0)


# --- SQLite foreign keys ON ---
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):
        cur = dbapi_connection.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SECRET_KEY = os.environ.get('SECRET_KEY', 'this_is_a_secret_password_to_enter_the_layer')
PROXMOX_HOST = os.environ.get('PROXMOX_HOST', "pve1.delogrand.com")
PROXMOX_USERNAME = os.environ.get('PROXMOX_USERNAME', "backend@pve")
PROXMOX_PASSWORD = os.environ.get('PROXMOX_PASSWORD', "123!@#qweQWEasdASDzxcZXC")
PROXMOX_TOKEN_ID = os.environ.get('PROXMOX_TOKEN_ID', "backend@pve!portal")
PROXMOX_TOKEN_SECRET = os.environ.get('PROXMOX_TOKEN_SECRET', "05987450-2518-4517-bfc4-5451eec046f9")
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', '123!@#qweQWEasdASDzxcZXC')
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
ENGINE_API_TOKEN = os.environ.get('ENGINE_API_TOKEN', 'changeme-please')
HEARTBEAT_INTERVAL_SECONDS = int(os.environ.get('HEARTBEAT_INTERVAL_SECONDS', 300))

# Verify the Proxmox certificate? Set to "true" once you have a real/known CA.
PVE_VERIFY = os.environ.get('PROXMOX_VERIFY_TLS', 'false').lower() == 'true'

# "proxy"  -> serve noVNC from this app and tunnel the websocket ourselves (recommended)
# "direct" -> old behaviour: iframe the Proxmox UI (requires same-site cookies; usually broken)
CONSOLE_MODE = os.environ.get('CONSOLE_MODE', 'proxy').lower()

# How long a minted console session may sit unclaimed before we drop it.
CONSOLE_SESSION_TTL = int(os.environ.get('CONSOLE_SESSION_TTL', 60))

# Power controls in the console toolbar. Master switch + per-action allow list,
# so you can pull power management mid-competition without a redeploy.
# NOTE: snapshot / rollback is deliberately NOT exposed anywhere here — a team
# that can roll back can undo a red-team compromise.
ALLOW_POWER_CONTROLS = os.environ.get('ALLOW_POWER_CONTROLS', 'true').lower() == 'true'
ALLOWED_POWER_ACTIONS = {
    a.strip().lower()
    for a in os.environ.get('ALLOWED_POWER_ACTIONS', 'start,shutdown,reboot,reset,stop').split(',')
    if a.strip()
}

# action -> (api sub-path, which vm types support it, is it a hard/destructive op)
POWER_ACTIONS = {
    'start':    ('status/start',    {'qemu', 'lxc'}, False),
    'shutdown': ('status/shutdown', {'qemu', 'lxc'}, False),
    'reboot':   ('status/reboot',   {'qemu', 'lxc'}, False),
    'reset':    ('status/reset',    {'qemu'},        True),
    'stop':     ('status/stop',     {'qemu', 'lxc'}, True),
}

# Key combos the toolbar may push through the Proxmox sendkey API (qemu only).
# Whitelisted so a crafted request can't hand arbitrary strings to qm sendkey.
SENDKEY_WHITELIST = {
    'ctrl-alt-delete', 'ctrl-alt-f1', 'ctrl-alt-f2', 'ctrl-alt-f3',
    'ctrl-alt-f4', 'ctrl-alt-f5', 'ctrl-alt-f6', 'ctrl-alt-f7',
    'esc', 'tab', 'ret', 'spc', 'f2', 'f8', 'f10', 'f12',
    'delete', 'print',
}

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///main.db'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "connect_args": {"check_same_thread": False, "timeout": 30}
}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Cookie settings: for local HTTP testing keep secure=False; set True behind HTTPS.
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db.init_app(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

sock = Sock(app) if _HAS_FLASK_SOCK else None


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def commit_with_retry(tries=5, base_delay=0.2):
    """Commit with simple backoff to avoid transient SQLite locks."""
    for i in range(tries):
        try:
            db.session.commit()
            return
        except OperationalError:
            db.session.rollback()
            time.sleep(base_delay * (2 ** i))
    db.session.commit()


def get_or_create_team(name: str) -> Team:
    team = Team.query.filter_by(name=name).first()
    if team:
        return team
    team = Team(name=name)
    db.session.add(team)
    try:
        commit_with_retry()
        return team
    except IntegrityError:
        db.session.rollback()
        existing = Team.query.filter_by(name=name).first()
        if existing:
            return existing
        raise


def get_or_create_image(name: str) -> VMImage:
    img = VMImage.query.filter_by(name=name).first()
    if img:
        return img
    img = VMImage(name=name)
    db.session.add(img)
    commit_with_retry()
    return img


def parse_iso(ts: str):
    if not ts:
        return None
    ts = ts.strip()
    if ts.endswith('Z'):
        ts = ts[:-1] + '+00:00'
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def engine_auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        token = auth.split(' ', 1)[1] if auth.startswith('Bearer ') else auth
        if token != ENGINE_API_TOKEN:
            return {"error": "Unauthorized"}, 401
        return f(*args, **kwargs)
    return wrapper


def recompute_user_web(user_id: int):
    """Sum the BEST score per challenge for this user (prevents double-counting)."""
    rows = (db.session.query(WebSubmission.challenge_id, func.max(WebSubmission.score_awarded))
            .filter(WebSubmission.user_id == user_id)
            .group_by(WebSubmission.challenge_id)
            .all())
    total = sum((mx or 0) for _, mx in rows)
    u = db.session.get(User, user_id)
    if u:
        u.web = int(total)
        u.update_total_score()
        commit_with_retry()


def get_or_404(model, ident):
    obj = db.session.get(model, ident)
    if obj is None:
        abort(404)
    return obj


def pve_url(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return f"https://{PROXMOX_HOST}/api2/json{path}"


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
with app.app_context():
    try:
        db.create_all()
        existing_admin = User.query.filter_by(username=ADMIN_USERNAME).first()
        if not existing_admin:
            hashed = generate_password_hash(ADMIN_PASSWORD)
            admin_user = User(
                team_name=ADMIN_USERNAME,
                username=ADMIN_USERNAME,
                password=hashed,
                team_id=None
            )
            db.session.add(admin_user)
            db.session.commit()
            app.logger.info("Admin user created.")
        else:
            app.logger.info("Admin user already exists.")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating database: {e}")

    if CONSOLE_MODE == 'proxy':
        if not (_HAS_FLASK_SOCK and _HAS_WS_CLIENT):
            app.logger.warning(
                "CONSOLE_MODE=proxy but flask-sock / websocket-client are missing. "
                "Run: pip install flask-sock websocket-client"
            )
        if not os.path.isdir(os.path.join('static', 'novnc', 'core')):
            app.logger.warning(
                "static/novnc not found. Run: "
                "git clone --depth 1 https://github.com/novnc/noVNC.git static/novnc"
            )


# ---------------------------------------------------------------------------
# Proxmox API plumbing
# ---------------------------------------------------------------------------
def get_proxmox_auth_headers():
    return {"Authorization": f"PVEAPIToken={PROXMOX_TOKEN_ID}={PROXMOX_TOKEN_SECRET}"}


def create_proxmox_user(userid, password, comment="Team user"):
    url = pve_url("/access/users")
    data = {"userid": userid, "password": password, "comment": comment}
    try:
        response = requests.post(url, headers=get_proxmox_auth_headers(), data=data, verify=PVE_VERIFY)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        app.logger.error(f"Error creating Proxmox user: {e}")
        return {"error": str(e)}


# --- tiny TTL cache so page loads don't hammer the cluster --------------------
_CACHE = {}
_CACHE_LOCK = threading.Lock()


def _cached(key, ttl, producer):
    now = time.time()
    with _CACHE_LOCK:
        hit = _CACHE.get(key)
        if hit and (now - hit[0]) < ttl:
            return hit[1]
    value = producer()
    with _CACHE_LOCK:
        _CACHE[key] = (now, value)
    return value


def fetch_proxmox_vms(use_cache=True):
    """
    Returns cluster resources for VMs *and* containers.
    Each entry carries 'type' ('qemu' or 'lxc') and 'pool' when set.
    """
    def _do():
        try:
            response = requests.get(pve_url("/cluster/resources?type=vm"),
                                    headers=get_proxmox_auth_headers(), verify=PVE_VERIFY)
            response.raise_for_status()
            return response.json().get("data", []) or []
        except Exception as e:
            app.logger.error(f"Error fetching VMs from Proxmox: {e}")
            return []
    return _cached("cluster_vms", 5, _do) if use_cache else _do()


def fetch_proxmox_acls(use_cache=True):
    def _do():
        try:
            response = requests.get(pve_url("/access/acl"),
                                    headers=get_proxmox_auth_headers(), verify=PVE_VERIFY)
            response.raise_for_status()
            return response.json().get("data", []) or []
        except Exception as e:
            app.logger.error(f"Error fetching ACLs from Proxmox: {e}")
            return []
    return _cached("acls", 10, _do) if use_cache else _do()


def fetch_user_groups(userid: str):
    """Groups a Proxmox user belongs to, so group-scoped ACLs are honoured too."""
    def _do():
        try:
            response = requests.get(pve_url(f"/access/users/{quote(userid, safe='')}"),
                                    headers=get_proxmox_auth_headers(), verify=PVE_VERIFY)
            response.raise_for_status()
            groups = (response.json().get("data") or {}).get("groups") or []
            if isinstance(groups, str):
                groups = [g for g in groups.split(',') if g]
            return [g.lower() for g in groups]
        except Exception as e:
            app.logger.debug(f"Could not fetch groups for {userid}: {e}")
            return []
    return _cached(f"groups:{userid.lower()}", 30, _do)


def vm_endpoint(vmtype: str) -> str:
    """'qemu' or 'lxc' — never hardcode this again."""
    return 'lxc' if (vmtype or '').lower() == 'lxc' else 'qemu'


def fetch_vm_config(node, vmid, vmtype='qemu'):
    url = pve_url(f"/nodes/{node}/{vm_endpoint(vmtype)}/{vmid}/config")
    try:
        response = requests.get(url, headers=get_proxmox_auth_headers(), verify=PVE_VERIFY)
        response.raise_for_status()
        return response.json().get("data", {}) or {}
    except Exception as e:
        current_app.logger.error(f"Error fetching config for {vmtype}/{vmid} on {node}: {e}")
        return {}


def get_session_ticket():
    """
    Ticket-based auth. API tokens cannot open a vncwebsocket, so this stays
    username/password. The ticket never reaches the browser in proxy mode.
    """
    data = {"username": PROXMOX_USERNAME, "password": PROXMOX_PASSWORD}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        response = requests.post(pve_url("/access/ticket"), data=data,
                                 headers=headers, verify=PVE_VERIFY)
        response.raise_for_status()
        return response.json()["data"]
    except Exception as e:
        current_app.logger.error(f"Error retrieving session ticket: {e}")
        return None


def pve_request(method, path, data=None, timeout=15):
    """
    Generic token-authenticated call. Returns (ok, payload_or_error_string).
    Power operations and status reads work fine with an API token; only the
    vncwebsocket needs a real ticket.
    """
    try:
        resp = requests.request(
            method, pve_url(path),
            headers=get_proxmox_auth_headers(),
            data=data or {},
            verify=PVE_VERIFY,
            timeout=timeout,
        )
        if resp.status_code >= 400:
            detail = ''
            try:
                detail = (resp.json() or {}).get('errors') or resp.text[:300]
            except Exception:
                detail = resp.text[:300]
            return False, f"{resp.status_code}: {detail}"
        return True, (resp.json() or {}).get('data')
    except Exception as e:
        return False, str(e)


def vm_supports_vnc_clipboard(cfg: dict, vmtype: str) -> bool:
    """
    Proxmox only bridges the guest clipboard when the VM's vga line carries
    'clipboard=vnc' (which starts the qemu vdagent). Containers never do.
    """
    if vmtype != 'qemu':
        return False
    return 'clipboard=vnc' in (cfg.get('vga') or '').replace(' ', '').lower()


def get_vnc_ticket_with_session(node, vmid, ticket, csrf_token, vmtype='qemu'):
    url = pve_url(f"/nodes/{node}/{vm_endpoint(vmtype)}/{vmid}/vncproxy")
    cookies = {"PVEAuthCookie": ticket}
    headers = {"CSRFPreventionToken": csrf_token,
               "Content-Type": "application/x-www-form-urlencoded"}
    data = {"websocket": "1", "generate-password": "0"}
    try:
        response = requests.post(url, cookies=cookies, headers=headers,
                                 data=data, verify=PVE_VERIFY)
        response.raise_for_status()
        return response.json()["data"]
    except Exception as e:
        current_app.logger.error(
            f"Error fetching VNC ticket for {vmtype}/{vmid} on {node}: {e}")
        return None


# ---------------------------------------------------------------------------
# Authorization: which VMs may this portal user touch?
# ---------------------------------------------------------------------------
def user_is_admin(user) -> bool:
    return bool(user and user.is_authenticated and
                (user.username or '').lower() == ADMIN_USERNAME.lower())


def user_allowed_vmids(user) -> set:
    """
    Resolve the Proxmox ACLs that apply to this portal user's matching PVE
    account, including group-scoped and pool-scoped grants.
    """
    if user_is_admin(user):
        return {int(vm.get("vmid")) for vm in fetch_proxmox_vms() if vm.get("vmid") is not None}

    proxmox_user = f"{(user.team_name or '').lower()}@pve"
    groups = set(fetch_user_groups(proxmox_user))

    allowed_vmids = set()
    allowed_pools = set()

    for acl in fetch_proxmox_acls():
        ugid = (acl.get("ugid") or "").lower()
        atype = (acl.get("type") or "user").lower()

        if atype == "user" and ugid != proxmox_user:
            continue
        if atype == "group" and ugid not in groups:
            continue
        if atype not in ("user", "group"):
            continue

        path = acl.get("path", "") or ""
        if path.startswith("/vms/"):
            try:
                allowed_vmids.add(int(path[len("/vms/"):]))
            except ValueError:
                current_app.logger.debug(f"Unparseable ACL path: {path}")
        elif path.startswith("/pool/"):
            allowed_pools.add(path[len("/pool/"):].lower())

    if allowed_pools:
        for vm in fetch_proxmox_vms():
            pool = (vm.get("pool") or "").lower()
            if pool and pool in allowed_pools and vm.get("vmid") is not None:
                allowed_vmids.add(int(vm["vmid"]))

    return allowed_vmids


def find_vm(vmid: int):
    for vm in fetch_proxmox_vms():
        if vm.get("vmid") == vmid:
            return vm
    return None


def authorized_vm_or_none(user, vmid: int):
    """
    THE gate. Every console path goes through this — a logged-in team must not
    be able to reach another team's box by typing a different vmid.
    """
    if not (user and user.is_authenticated):
        return None
    if vmid not in user_allowed_vmids(user):
        current_app.logger.warning(
            f"DENY console: user={user.username!r} vmid={vmid} not in ACL set")
        return None
    return find_vm(vmid)


# ---------------------------------------------------------------------------
# Login manager / decorators
# ---------------------------------------------------------------------------
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not user_is_admin(current_user):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/register/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        team_name = request.form['team_name'].strip()
        password = request.form['password']

        if team_name.lower() == ADMIN_USERNAME.lower():
            flash("That team name is reserved.", "error")
            return redirect(url_for('register'))

        if User.query.filter_by(team_name=team_name).first():
            flash("Team name already registered!", "error")
            return redirect(url_for('register'))

        team_obj = get_or_create_team(team_name)

        proxmox_userid = f"{team_name.lower()}@pve"
        try:
            create_proxmox_user(proxmox_userid, password)
        except Exception:
            pass  # already logged

        new_user = User(
            username=team_name,
            team_name=team_name,
            password=generate_password_hash(password),
            team_id=team_obj.id
        )
        db.session.add(new_user)
        db.session.commit()

        for service in Service.query.all():
            db.session.add(ServiceStatus(team_id=team_obj.id, service_id=service.id, status=False))
        db.session.commit()

        flash("Team registered successfully! Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        team_name = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(team_name=team_name).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('announcements'))
        flash("Invalid team name or password", "error")
    return render_template('login.html')


@app.route('/logout/')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/announcements/')
@login_required
def announcements():
    posts = Announcement.query.order_by(Announcement.timestamp.desc()).all()
    web_challenges = WebChallenge.query.order_by(WebChallenge.timestamp.desc()).all()
    injects = Inject.query.order_by(Inject.timestamp.desc()).all()
    return render_template(
        'announcements.html',
        posts=posts,
        web_challenges=web_challenges,
        injects=injects,
        datetime=datetime,
        timedelta=timedelta
    )


@app.route('/announcement/<int:announcement_id>/')
@login_required
def announcement_detail(announcement_id):
    announcement = get_or_404(Announcement, announcement_id)
    return render_template('announcement_detail.html', announcement=announcement)


@app.route('/scoreboard/')
@login_required
def scoreboard():
    teams = User.query.filter(User.username != ADMIN_USERNAME).order_by(User.team_name.asc()).all()
    return render_template('scoreboard.html', teams=teams)


@app.route('/status/')
@login_required
def status():
    teams = Team.query.order_by(Team.name.asc()).all()
    services = Service.query.order_by(Service.id).all()
    statuses = ServiceStatus.query.all()
    status_map = {(s.team_id, s.service_id): s.status for s in statuses}
    return render_template('status.html', teams=teams, services=services, status_map=status_map)


@app.route('/vms/')
@login_required
def vms():
    allowed = user_allowed_vmids(current_user)
    app.logger.info(f"Allowed VM IDs for {current_user.username}: {sorted(allowed)}")

    team_vms = []
    for vm in fetch_proxmox_vms():
        vmid = vm.get("vmid")
        if vmid not in allowed:
            continue

        node = vm.get("node")
        vmtype = vm_endpoint(vm.get("type"))
        cfg = fetch_vm_config(node, vmid, vmtype)

        team_vms.append({
            "name": cfg.get("name") or cfg.get("hostname") or vm.get("name") or "Unknown",
            "node": node,
            "vmid": vmid,
            "type": vmtype,
            "kind": "Container" if vmtype == "lxc" else "VM",
            "status": vm.get("status", "unknown"),
            "cores": cfg.get("cores", "N/A"),
        })

    team_vms.sort(key=lambda v: v["vmid"])
    return render_template('vms.html', vms=team_vms, console_mode=CONSOLE_MODE)


# ---------------------------------------------------------------------------
# Console — proxy mode
#
# Flow:
#   1. GET  /console/<vmid>/            -> ACL check, render noVNC shell
#   2. POST /api/console/<vmid>/session -> mint vncproxy NOW, return {sid, password}
#   3. WS   /ws/vnc/<sid>               -> tunnel raw frames to Proxmox
#
# Minting in step 2 (not step 1) matters: Proxmox kills an unclaimed vncproxy
# after ~10 seconds, so the clock must not start while noVNC is still loading.
# ---------------------------------------------------------------------------
_CONSOLE_SESSIONS = {}
_CONSOLE_LOCK = threading.Lock()


def _reap_console_sessions():
    now = time.time()
    with _CONSOLE_LOCK:
        dead = [k for k, v in _CONSOLE_SESSIONS.items()
                if (now - v["created"]) > CONSOLE_SESSION_TTL]
        for k in dead:
            _CONSOLE_SESSIONS.pop(k, None)


@app.route('/console/<int:vmid>/')
@login_required
def console(vmid):
    if CONSOLE_MODE != 'proxy':
        return redirect(url_for('view_webconsole', vmid=vmid))

    vm = authorized_vm_or_none(current_user, vmid)
    if not vm:
        flash("VM not found or you don't have permission.", "error")
        return redirect(url_for('vms'))

    if not (_HAS_FLASK_SOCK and _HAS_WS_CLIENT):
        flash("Console proxy is not installed on the server "
              "(pip install flask-sock websocket-client).", "error")
        return redirect(url_for('vms'))

    vmtype = vm_endpoint(vm.get("type"))
    cfg = fetch_vm_config(vm.get("node"), vmid, vmtype)
    vm_name = cfg.get("name") or cfg.get("hostname") or vm.get("name") or f"{vmtype}-{vmid}"

    power_actions = sorted(
        a for a, (_, types, _) in POWER_ACTIONS.items()
        if ALLOW_POWER_CONTROLS and a in ALLOWED_POWER_ACTIONS and vmtype in types
    ) if ALLOW_POWER_CONTROLS else []

    return render_template(
        'console.html',
        vmid=vmid,
        vm_name=vm_name,
        vmtype=vmtype,
        node=vm.get("node"),
        power_actions=power_actions,
        clipboard_ready=vm_supports_vnc_clipboard(cfg, vmtype),
        sendkey_ok=(vmtype == 'qemu'),
    )


@app.route('/api/console/<int:vmid>/session', methods=['POST'])
@login_required
def api_console_session(vmid):
    """Mint a one-shot console session. Returns the id to dial and the VNC password."""
    vm = authorized_vm_or_none(current_user, vmid)
    if not vm:
        return jsonify(error="Not found or not permitted"), 403

    node = vm.get("node")
    vmtype = vm_endpoint(vm.get("type"))

    sess = get_session_ticket()
    if not sess:
        return jsonify(error="Could not authenticate to Proxmox"), 502

    vnc = get_vnc_ticket_with_session(node, vmid, sess.get("ticket"),
                                      sess.get("CSRFPreventionToken"), vmtype)
    if not vnc:
        return jsonify(error="Proxmox refused the console request"), 502

    _reap_console_sessions()
    sid = secrets.token_urlsafe(24)
    with _CONSOLE_LOCK:
        _CONSOLE_SESSIONS[sid] = {
            "user_id": current_user.id,
            "node": node,
            "vmid": vmid,
            "vmtype": vmtype,
            "port": vnc.get("port"),
            "vncticket": vnc.get("ticket"),
            "authcookie": sess.get("ticket"),
            "created": time.time(),
        }

    # The vncticket doubles as the VNC password on the QEMU/LXC side, so the
    # browser does need this one. It is single-use and dies with the session;
    # the PVEAuthCookie (which would unlock the whole cluster) stays server-side.
    return jsonify(sid=sid, password=vnc.get("ticket"))


@app.route('/api/console/<int:vmid>/status', methods=['GET'])
@login_required
def api_console_status(vmid):
    """Live power state for the toolbar pill."""
    vm = authorized_vm_or_none(current_user, vmid)
    if not vm:
        return jsonify(error="Not found or not permitted"), 403

    vmtype = vm_endpoint(vm.get("type"))
    ok, data = pve_request('GET', f"/nodes/{vm.get('node')}/{vmtype}/{vmid}/status/current")
    if not ok:
        return jsonify(error=data), 502

    return jsonify(
        status=(data or {}).get('status'),
        uptime=(data or {}).get('uptime'),
        qmpstatus=(data or {}).get('qmpstatus'),
        agent=bool((data or {}).get('agent')),
    )


@app.route('/api/console/<int:vmid>/power', methods=['POST'])
@login_required
def api_console_power(vmid):
    """start / shutdown / reboot / reset / stop, gated by ACL and allow list."""
    if not ALLOW_POWER_CONTROLS:
        return jsonify(error="Power controls are disabled"), 403

    vm = authorized_vm_or_none(current_user, vmid)
    if not vm:
        return jsonify(error="Not found or not permitted"), 403

    payload = request.get_json(silent=True) or {}
    action = (payload.get('action') or '').strip().lower()

    if action not in POWER_ACTIONS:
        return jsonify(error="Unknown action"), 400
    if action not in ALLOWED_POWER_ACTIONS:
        return jsonify(error=f"'{action}' is not enabled on this portal"), 403

    sub_path, types, destructive = POWER_ACTIONS[action]
    vmtype = vm_endpoint(vm.get("type"))
    if vmtype not in types:
        return jsonify(error=f"'{action}' is not supported for {vmtype}"), 400

    # Audit trail: who pulled the trigger on what, and when.
    app.logger.warning(
        "POWER %s by user=%r team=%r on %s/%s (%s)%s",
        action.upper(), current_user.username, current_user.team_name,
        vmtype, vmid, vm.get('node'), "  [destructive]" if destructive else ""
    )

    ok, data = pve_request('POST', f"/nodes/{vm.get('node')}/{vmtype}/{vmid}/{sub_path}", timeout=25)
    if not ok:
        return jsonify(error=data), 502

    return jsonify(ok=True, action=action, task=data)


@app.route('/api/console/<int:vmid>/sendkey', methods=['POST'])
@login_required
def api_console_sendkey(vmid):
    """
    Out-of-band key injection via the Proxmox sendkey API (qemu only).
    Useful when the browser swallows a combo before noVNC ever sees it.
    """
    vm = authorized_vm_or_none(current_user, vmid)
    if not vm:
        return jsonify(error="Not found or not permitted"), 403

    vmtype = vm_endpoint(vm.get("type"))
    if vmtype != 'qemu':
        return jsonify(error="sendkey is only available for VMs, not containers"), 400

    key = (request.get_json(silent=True) or {}).get('key', '').strip().lower()
    if key not in SENDKEY_WHITELIST:
        return jsonify(error="Key not permitted"), 400

    ok, data = pve_request('PUT', f"/nodes/{vm.get('node')}/qemu/{vmid}/sendkey",
                           data={'key': key})
    if not ok:
        return jsonify(error=data), 502
    return jsonify(ok=True, key=key)


def _upstream_to_browser(up, ws):
    try:
        while True:
            data = up.recv()
            if data is None or data == b"":
                break
            if isinstance(data, str):
                data = data.encode("utf-8", errors="ignore")
            ws.send(data)
    except Exception:
        pass
    finally:
        for closer in (ws.close, up.close):
            try:
                closer()
            except Exception:
                pass


if sock is not None:
    @sock.route('/ws/vnc/<sid>')
    def ws_vnc(ws, sid):
        if not (current_user.is_authenticated and _HAS_WS_CLIENT):
            return

        with _CONSOLE_LOCK:
            meta = _CONSOLE_SESSIONS.pop(sid, None)  # single use

        if not meta:
            app.logger.warning("console ws: unknown or expired session id")
            return
        if meta["user_id"] != current_user.id:
            app.logger.warning("console ws: session id presented by the wrong user")
            return
        if (time.time() - meta["created"]) > CONSOLE_SESSION_TTL:
            app.logger.warning("console ws: session expired before pickup")
            return

        url = (
            f"wss://{PROXMOX_HOST}/api2/json/nodes/{meta['node']}"
            f"/{meta['vmtype']}/{meta['vmid']}/vncwebsocket"
            f"?port={meta['port']}&vncticket={quote(meta['vncticket'], safe='')}"
        )

        try:
            up = wsclient.create_connection(
                url,
                header=[f"Cookie: PVEAuthCookie={quote(meta['authcookie'], safe='')}"],
                subprotocols=["binary"],
                sslopt={"cert_reqs": ssl.CERT_NONE} if not PVE_VERIFY else {},
                origin=f"https://{PROXMOX_HOST}",
                enable_multithread=True,
                timeout=15,
            )
            up.settimeout(None)
        except Exception as e:
            app.logger.error(f"console ws: upstream connect failed for "
                             f"{meta['vmtype']}/{meta['vmid']}: {e}")
            return

        app.logger.info(f"console ws: {current_user.username} -> "
                        f"{meta['node']}/{meta['vmtype']}/{meta['vmid']}")

        t = threading.Thread(target=_upstream_to_browser, args=(up, ws), daemon=True)
        t.start()

        try:
            while True:
                data = ws.receive()
                if data is None:
                    break
                if isinstance(data, str):
                    data = data.encode("utf-8", errors="ignore")
                up.send_binary(data)
        except Exception:
            pass
        finally:
            try:
                up.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Console — legacy direct mode (kept for fallback / comparison)
#
# This only works if the portal and Proxmox share a parent domain over HTTPS
# *and* the browser still accepts third-party cookies. Prefer proxy mode.
# ---------------------------------------------------------------------------
@app.route('/webconsole/<int:vmid>/')
@login_required
def view_webconsole(vmid):
    if CONSOLE_MODE == 'proxy':
        return redirect(url_for('console', vmid=vmid))

    vm = authorized_vm_or_none(current_user, vmid)
    if not vm:
        flash("VM not found or you don't have permission.", "error")
        return redirect(url_for('vms'))

    node = vm.get("node")
    vmtype = vm_endpoint(vm.get("type"))
    cfg = fetch_vm_config(node, vmid, vmtype)
    vm_name = cfg.get("name") or cfg.get("hostname") or f"{vmtype}-{vmid}"

    session_data = get_session_ticket()
    if not session_data:
        flash("Error retrieving session ticket.", "error")
        return redirect(url_for('vms'))
    session_ticket = session_data.get("ticket")
    csrf_token = session_data.get("CSRFPreventionToken")

    vnc_data = get_vnc_ticket_with_session(node, vmid, session_ticket, csrf_token, vmtype)
    if not vnc_data:
        flash("Error retrieving VNC session information.", "error")
        return redirect(url_for('vms'))

    port = vnc_data.get("port")
    encoded_vnc_ticket = quote_plus(vnc_data.get("ticket"))
    console_kind = "lxc" if vmtype == "lxc" else "kvm"
    vnc_url = (
        f"https://{PROXMOX_HOST}/?"
        f"console={console_kind}&novnc=1&node={node}&resize=on&vmid={vmid}"
        f"&path=api2/json/nodes/{node}/{vmtype}/{vmid}"
        f"/vncwebsocket/port/{port}/vncticket/{encoded_vnc_ticket}"
    )

    response = make_response(render_template('webconsole.html', vnc_url=vnc_url, vm_name=vm_name))
    cookie_domain = os.environ.get("COOKIE_DOMAIN") or None
    response.set_cookie(
        "PVEAuthCookie",
        session_ticket,
        max_age=7200,
        path="/",
        domain=cookie_domain,   # must be a parent of BOTH hosts, or this is pointless
        secure=True,
        httponly=True,
        samesite="None"
    )
    return response


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------
@app.route('/admin/')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin/dashboard.html')


@app.route('/admin/announcements/new/', methods=['GET', 'POST'])
@login_required
@admin_required
def create_announcement():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        file = request.files.get('file')
        file_link = None
        if file and file.filename:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            file_link = filename
        db.session.add(Announcement(title=title, content=content, file_link=file_link))
        db.session.commit()
        flash('Announcement created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin/create_announcement.html')


@app.route('/admin/announcements/', methods=['GET'])
@login_required
@admin_required
def manage_announcements():
    items = Announcement.query.order_by(Announcement.timestamp.desc()).all()
    return render_template('admin/manage_announcements.html', items=items)


@app.route('/admin/announcements/edit/<int:item_id>/', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_announcement(item_id):
    item = get_or_404(Announcement, item_id)
    if request.method == 'POST':
        item.title = request.form['title'].strip()
        item.content = request.form['content'].strip()
        file = request.files.get('file')
        if file and file.filename:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            item.file_link = filename
        db.session.commit()
        flash('Announcement updated.', 'success')
        return redirect(url_for('manage_announcements'))
    return render_template('admin/edit_announcement.html', item=item)


@app.route('/admin/announcements/delete/<int:item_id>/', methods=['POST'])
@login_required
@admin_required
def delete_announcement(item_id):
    item = get_or_404(Announcement, item_id)
    db.session.delete(item)
    db.session.commit()
    flash('Announcement deleted.', 'success')
    return redirect(url_for('manage_announcements'))


@app.route('/admin/injects/', methods=['GET'])
@login_required
@admin_required
def manage_injects():
    items = Inject.query.order_by(Inject.timestamp.desc()).all()
    return render_template('admin/manage_injects.html', items=items)


@app.route('/admin/injects/edit/<int:item_id>/', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_inject(item_id):
    item = get_or_404(Inject, item_id)
    if request.method == 'POST':
        item.title = request.form['title'].strip()
        try:
            item.countdown_minutes = int(request.form.get('countdown', item.countdown_minutes))
        except ValueError:
            pass
        item.status = request.form.get('status', item.status)
        file = request.files.get('file')
        if file and file.filename:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            item.file_link = filename
        db.session.commit()
        flash('Inject updated.', 'success')
        return redirect(url_for('manage_injects'))
    return render_template('admin/edit_inject.html', item=item)


@app.route('/admin/injects/delete/<int:item_id>/', methods=['POST'])
@login_required
@admin_required
def delete_inject(item_id):
    item = get_or_404(Inject, item_id)
    service = Service.query.filter_by(name=f"Inject-{item.id}").first()
    if service:
        ServiceStatus.query.filter_by(service_id=service.id).delete()
        db.session.delete(service)
    db.session.delete(item)
    db.session.commit()
    flash('Inject deleted (and related service/status entries removed).', 'success')
    return redirect(url_for('manage_injects'))


@app.route('/admin/injects/new/', methods=['GET', 'POST'])
@login_required
@admin_required
def create_inject():
    if request.method == 'POST':
        title = request.form['title']
        try:
            countdown = int(request.form.get('countdown', 0))
        except ValueError:
            countdown = 0
        status_value = request.form.get('status', 'Offline')
        file = request.files.get('file')
        file_link = None
        if file and file.filename:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            file_link = filename

        new_inject = Inject(title=title, countdown_minutes=countdown,
                            status=status_value, file_link=file_link)
        db.session.add(new_inject)
        db.session.commit()

        inject_service = Service(name=f"Inject-{new_inject.id}")
        db.session.add(inject_service)
        db.session.commit()

        for team in Team.query.all():
            if not ServiceStatus.query.filter_by(team_id=team.id, service_id=inject_service.id).first():
                db.session.add(ServiceStatus(team_id=team.id, service_id=inject_service.id, status=False))
        db.session.commit()

        flash('Inject created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin/create_inject.html')


@app.route('/admin/web-challenges/', methods=['GET'])
@login_required
@admin_required
def manage_web_challenges():
    items = WebChallenge.query.order_by(WebChallenge.timestamp.desc()).all()
    return render_template('admin/manage_web_challenges.html', items=items)


@app.route('/admin/web-challenges/edit/<int:item_id>/', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_web_challenge(item_id):
    item = get_or_404(WebChallenge, item_id)
    if request.method == 'POST':
        item.title = request.form['title'].strip()
        try:
            item.score = int(request.form.get('score', item.score))
        except ValueError:
            pass
        item.status = request.form.get('status', item.status)
        file = request.files.get('file')
        if file and file.filename:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            item.file_link = filename
        db.session.commit()
        flash('Web Challenge updated.', 'success')
        return redirect(url_for('manage_web_challenges'))
    return render_template('admin/edit_web_challenge.html', item=item)


@app.route('/admin/web-challenges/delete/<int:item_id>/', methods=['POST'])
@login_required
@admin_required
def delete_web_challenge(item_id):
    item = get_or_404(WebChallenge, item_id)
    WebSubmission.query.filter_by(challenge_id=item.id).delete()
    db.session.delete(item)
    db.session.commit()
    flash('Web Challenge and related submissions deleted.', 'success')
    return redirect(url_for('manage_web_challenges'))


@app.route('/admin/web-challenges/new/', methods=['GET', 'POST'])
@login_required
@admin_required
def create_web_challenge():
    if request.method == 'POST':
        title = request.form['title']
        try:
            score = int(request.form.get('score', 0))
        except ValueError:
            score = 0
        file = request.files.get('file')
        file_link = None
        if file and file.filename:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            file_link = filename
        db.session.add(WebChallenge(title=title, score=score, file_link=file_link))
        db.session.commit()
        flash('Web Challenge created successfully.', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin/create_web_challenge.html')


@app.route('/admin/web-submissions/')
@login_required
@admin_required
def view_web_submissions():
    submissions = WebSubmission.query.order_by(WebSubmission.timestamp.desc()).all()
    return render_template('admin/view_submissions.html', submissions=submissions)


@app.route('/web-challenge/<int:challenge_id>/', methods=['GET', 'POST'])
@login_required
def view_web_challenge(challenge_id):
    challenge = get_or_404(WebChallenge, challenge_id)
    submission = None
    if request.method == 'POST':
        flag = (request.form.get('flag') or '').strip() or None
        file = request.files.get('file')

        saved_path = None
        if file and file.filename:
            fname = secure_filename(file.filename)
            subdir = os.path.join(app.config['UPLOAD_FOLDER'], 'submissions')
            os.makedirs(subdir, exist_ok=True)
            unique = f"{int(time.time())}_{current_user.id}_{fname}"
            file.save(os.path.join(subdir, unique))
            saved_path = f"submissions/{unique}"

        submission = WebSubmission(
            user_id=current_user.id,
            challenge_id=challenge.id,
            submitted_flag=flag,
            submitted_file=saved_path,
            score_awarded=0
        )
        db.session.add(submission)
        db.session.commit()
        flash("Submission received!", "success")
    else:
        submission = WebSubmission.query \
            .filter_by(user_id=current_user.id, challenge_id=challenge.id) \
            .order_by(WebSubmission.timestamp.desc()).first()
    return render_template('web_challenge_detail.html', challenge=challenge, submission=submission)


@app.route('/admin/web-submissions/grade/<int:submission_id>/', methods=['POST'])
@login_required
@admin_required
def grade_submission(submission_id):
    submission = get_or_404(WebSubmission, submission_id)
    try:
        new_score = int(request.form['score'])
    except ValueError:
        flash("Invalid score.", "error")
        return redirect(url_for('view_web_submissions'))

    submission.score_awarded = new_score
    if submission.challenge:
        submission.challenge.status = "Graded"
    commit_with_retry()

    recompute_user_web(submission.user_id)

    flash("Submission graded and scoreboard updated.", "success")
    return redirect(url_for('view_web_submissions'))


@app.route('/inject/<int:inject_id>/')
@login_required
def view_inject(inject_id):
    inject = get_or_404(Inject, inject_id)
    service = Service.query.filter_by(name=f"Inject-{inject.id}").first()
    service_status = None
    if current_user.team and service:
        service_status = ServiceStatus.query.filter_by(
            team_id=current_user.team.id, service_id=service.id
        ).first()
    return render_template('inject_detail.html', inject=inject, service_status=service_status)


# ---------------------------------------------------------------------------
# Scoring API
# ---------------------------------------------------------------------------
@app.route('/api/score-events/', methods=['POST'])
@engine_auth_required
def api_score_events():
    data = request.get_json(force=True, silent=True) or {}
    team_name = data.get('team')
    team_id = data.get('team_id')
    image_name = data.get('image')
    image_id = data.get('image_id')
    delta = int(data.get('delta', 0))
    reason = (data.get('reason') or '').strip()
    ts = parse_iso(data.get('timestamp')) or datetime.utcnow()

    if not ((team_name or team_id) and (image_name or image_id) and delta):
        return {"error": "team/team_id, image/image_id and non-zero delta are required"}, 400

    team = None
    if team_id:
        team = db.session.get(Team, int(team_id))
    elif team_name:
        team = Team.query.filter_by(name=team_name).first()
    if not team:
        team = get_or_create_team(team_name)
    if not team:
        return {"error": "Team not found/created"}, 404

    image = None
    if image_id:
        image = db.session.get(VMImage, int(image_id))
    elif image_name:
        image = get_or_create_image(image_name)
    if not image:
        return {"error": "Image not found/created"}, 404

    ev = ImageScoreEvent(team_id=team.id, image_id=image.id, delta=delta,
                         reason=reason, timestamp=ts)
    db.session.add(ev)

    for u in team.users:
        u.image_scores = (u.image_scores or 0) + delta
        u.update_total_score()

    commit_with_retry()
    return {"ok": True, "event_id": ev.id}


@app.route('/api/service-status/bulk', methods=['POST'])
@engine_auth_required
def api_service_status_bulk():
    payload = request.get_json(force=True, silent=True) or {}
    updates = payload.get('updates', [])
    if not isinstance(updates, list) or not updates:
        return {"error": "Provide 'updates' list"}, 400

    changed = 0
    for u in updates:
        team_name = u.get('team')
        service_name = u.get('service')
        status_val = bool(u.get('status', False))
        if not (team_name and service_name):
            continue
        team = Team.query.filter_by(name=team_name).first() or get_or_create_team(team_name)
        service = Service.query.filter_by(name=service_name).first()
        if not service:
            service = Service(name=service_name)
            db.session.add(service)
            commit_with_retry()
        ss = ServiceStatus.query.filter_by(team_id=team.id, service_id=service.id).first()
        if not ss:
            db.session.add(ServiceStatus(team_id=team.id, service_id=service.id, status=status_val))
        else:
            ss.status = status_val
        changed += 1
        commit_with_retry()
    return {"ok": True, "updated": changed}


@app.route('/api/teams/<int:team_id>/image-scores', methods=['GET'])
@login_required
def api_team_image_scores(team_id):
    import re
    team = db.session.get(Team, team_id)
    if not team:
        return {"error": "Team not found"}, 404

    qs_from = request.args.get('from')
    qs_to = request.args.get('to')
    group = request.args.get('group', 'overall')

    t_from = parse_iso(qs_from) if qs_from else None
    t_to = parse_iso(qs_to) if qs_to else None

    q = ImageScoreEvent.query.filter(ImageScoreEvent.team_id == team_id)
    if t_from:
        q = q.filter(ImageScoreEvent.timestamp >= t_from)
    if t_to:
        q = q.filter(ImageScoreEvent.timestamp <= t_to)
    q = q.order_by(ImageScoreEvent.timestamp.asc(), ImageScoreEvent.id.asc())
    rows = q.all()

    baseline_overall = 0
    if t_from:
        bq = ImageScoreEvent.query.with_entities(
            func.coalesce(func.sum(ImageScoreEvent.delta), 0)
        ).filter(ImageScoreEvent.team_id == team_id,
                 ImageScoreEvent.timestamp < t_from)
        baseline_overall = int(bq.scalar() or 0)

    points_overall = []
    current_overall = baseline_overall

    def img_key(ev):
        return ev.image.name if ev.image else f"image:{ev.image_id}"

    img_baselines = {}
    if t_from:
        pre_rows = ImageScoreEvent.query.filter(
            ImageScoreEvent.team_id == team_id,
            ImageScoreEvent.timestamp < t_from
        ).all()
        for ev in pre_rows:
            key = img_key(ev)
            img_baselines[key] = img_baselines.get(key, 0) + int(ev.delta or 0)

    img_running = dict(img_baselines)
    img_series = {}
    img_penalties = {}
    img_Found = {}
    img_total = {}

    vulns_re = re.compile(r"engine report:\s*(\d+)\s*/\s*(\d+)\s*vulns", re.I)

    for ev in rows:
        d = int(ev.delta or 0)
        current_overall += d
        if group != 'image':
            points_overall.append({"t": ev.timestamp.isoformat(), "score": current_overall})

        key = img_key(ev)
        if key not in img_series:
            img_series[key] = []
            if key not in img_running:
                img_running[key] = 0
        img_running[key] += d
        img_series[key].append({"t": ev.timestamp.isoformat(), "score": img_running[key]})

        if d < 0:
            img_penalties[key] = img_penalties.get(key, 0) + d

        if ev.reason:
            m = vulns_re.search(ev.reason)
            if m:
                try:
                    img_Found[key] = int(m.group(1))
                    img_total[key] = int(m.group(2))
                except Exception:
                    pass

    if not rows:
        now_iso = datetime.utcnow().isoformat()
        if group == 'image':
            out = []
            for key, base in (img_baselines.items() or []):
                out.append({"name": key, "series": [
                    {"t": (t_from or now_iso), "score": base},
                    {"t": (t_to or now_iso), "score": base},
                ]})
            return {"team_id": team_id, "baseline": baseline_overall,
                    "series_by_image": out, "events": []}
        series = [
            {"t": (t_from or now_iso), "score": baseline_overall},
            {"t": (t_to or now_iso), "score": baseline_overall},
        ]
        return {"team_id": team_id, "baseline": baseline_overall,
                "series": series, "events": []}

    events_payload = [{
        "id": ev.id,
        "t": ev.timestamp.isoformat(),
        "delta": ev.delta,
        "image": (ev.image.name if ev.image else None),
        "reason": ev.reason
    } for ev in rows]

    if group == 'image':
        out = []
        for key, pts in img_series.items():
            Found = img_Found.get(key)
            total = img_total.get(key)
            Missed = (total - Found) if (Found is not None and total is not None) else None
            out.append({
                "name": key,
                "series": pts,
                "Found": Found,
                "Missed": Missed,
            })
        return {"team_id": team_id, "baseline": baseline_overall,
                "series_by_image": out, "events": events_payload}

    return {"team_id": team_id, "baseline": baseline_overall,
            "series": points_overall, "events": events_payload}


@app.route('/api/scoreboard/', methods=['GET'])
@login_required
def api_scoreboard_summary():
    users = User.query.filter(User.username != ADMIN_USERNAME) \
        .order_by(User.total.desc(), User.team_name.asc()).all()
    return {"teams": [{
        "user_id": u.id,
        "team_id": u.team_id,
        "team_name": u.team_name,
        "web": u.web,
        "uptime": u.uptime,
        "penalties": u.penalties,
        "image_scores": u.image_scores,
        "total": u.total
    } for u in users]}


@app.route('/scoreboard/prefetch')
@login_required
def scoreboard_prefetch():
    teams = User.query.filter(User.username != ADMIN_USERNAME) \
        .order_by(User.total.desc(), User.team_name.asc()).all()
    return render_template('prefetch/scoreboard_table_body.html', teams=teams)


@app.route('/scoreboard/team/<int:team_id>/')
@login_required
def team_scoreboard(team_id):
    team = db.session.get(Team, team_id)
    if not team:
        abort(404)
    today = datetime.utcnow().date()
    default_from = datetime(today.year, today.month, today.day).isoformat() + "Z"
    default_to = datetime.utcnow().isoformat() + "Z"
    user_ids = [u.id for u in (team.users or [])]
    subs = []
    if user_ids:
        subs = WebSubmission.query.filter(WebSubmission.user_id.in_(user_ids)) \
            .order_by(WebSubmission.timestamp.desc()).limit(50).all()
    return render_template('team_scoreboard.html', team=team, default_from=default_from,
                           default_to=default_to, submissions=subs)


# ---------------------------------------------------------------------------
# Admin: Users
# ---------------------------------------------------------------------------
@app.route('/admin/users/')
@login_required
@admin_required
def admin_users():
    users = User.query.filter(User.username != ADMIN_USERNAME) \
        .order_by(User.team_name.asc()).all()
    return render_template('admin/users.html', users=users, q='')


@app.route('/admin/users/new/', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_user_new():
    if request.method == 'POST':
        team_name = request.form['team_name'].strip()
        username = request.form['username'].strip()
        password = request.form.get('password', '').strip()
        if not team_name or not username or not password:
            flash("Team name, username, and password are required.", "error")
            return redirect(url_for('admin_user_new'))
        team = get_or_create_team(team_name)
        if User.query.filter((User.username == username) | (User.team_name == team_name)).first():
            flash("Username or Team name already exists.", "error")
            return redirect(url_for('admin_user_new'))
        db.session.add(User(
            team_name=team_name,
            username=username,
            password=generate_password_hash(password),
            team_id=team.id
        ))
        commit_with_retry()
        flash("User created.", "success")
        return redirect(url_for('admin_users'))
    return render_template('admin/edit_user.html', user=None)


@app.route('/admin/users/<int:user_id>/edit/', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_user_edit(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    if request.method == 'POST':
        new_team_name = request.form['team_name'].strip()
        new_username = request.form['username'].strip()
        if not new_team_name or not new_username:
            flash("Team name and username are required.", "error")
            return redirect(url_for('admin_user_edit', user_id=user.id))
        if user.team_name != new_team_name:
            team = get_or_create_team(new_team_name)
            user.team_name = new_team_name
            user.team_id = team.id
        user.username = new_username
        try:
            commit_with_retry()
            flash("User updated.", "success")
            return redirect(url_for('admin_users'))
        except IntegrityError:
            db.session.rollback()
            flash("Username or Team name must be unique.", "error")
    return render_template('admin/edit_user.html', user=user)


@app.route('/admin/users/<int:user_id>/password/', methods=['POST'])
@login_required
@admin_required
def admin_user_password(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    new_pw = request.form.get('password', '').strip()
    if not new_pw:
        flash("Password cannot be empty.", "error")
        return redirect(url_for('admin_user_edit', user_id=user.id))
    user.password = generate_password_hash(new_pw)
    commit_with_retry()
    flash("Password updated.", "success")
    return redirect(url_for('admin_user_edit', user_id=user.id))


@app.route('/admin/users/delete/<int:user_id>/', methods=['POST'])
@login_required
@admin_required
def admin_user_delete(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    if user.username.lower() == ADMIN_USERNAME.lower():
        flash("Refusing to delete the admin account.", "error")
        return redirect(url_for('admin_users'))
    team = user.team
    db.session.delete(user)
    try:
        db.session.flush()
        if team and len(team.users) == 0:
            db.session.delete(team)
        commit_with_retry()
        flash("User deleted.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Could not delete user: {e}", "error")
    return redirect(url_for('admin_users'))


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


@app.route('/status/prefetch')
@login_required
def status_partial():
    teams = Team.query.order_by(Team.name.asc()).all()
    services = Service.query.order_by(Service.id).all()
    statuses = ServiceStatus.query.all()
    status_map = {(s.team_id, s.service_id): s.status for s in statuses}
    return render_template('prefetch/status_table_body.html', teams=teams,
                           services=services, status_map=status_map)


# ---------------------------------------------------------------------------
# Scoring server endpoints
# ---------------------------------------------------------------------------
@app.route('/status/<team_id>/<image_name>', methods=['GET'])
def engine_status(team_id, image_name):
    accepting = os.environ.get("SCORE_ACCEPTING", "true").lower() != "false"

    team = Team.query.filter_by(name=team_id).first()
    if not team:
        return jsonify({"Status": "ERROR", "Error": "Unknown TeamID"}), 400

    if not accepting:
        return jsonify({"Status": "DISABLED"}), 200
    return jsonify({"Status": "OK"}), 200


@app.route('/update', methods=['POST'])
def engine_update():
    try:
        upd_hex = (request.form.get('update') or '').strip()

        if not upd_hex:
            j = request.get_json(silent=True)
            if isinstance(j, dict):
                upd_hex = (j.get('update') or '').strip()

        if not upd_hex:
            upd_hex = (request.get_data(cache=False, as_text=True) or '').strip()

        if not upd_hex:
            current_app.logger.warning("update missing; ct=%s", request.content_type)
            return jsonify(error="Missing 'update' payload"), 400

        try:
            outer_txt, used_encryption = _decrypt_outer(upd_hex, ENGINE_SHARED_KEY)
        except ValueError as e:
            current_app.logger.warning("decrypt Missed: %s", e)
            return jsonify(error=str(e)), 400

        kv = _parse_kv_delim(outer_txt)
        team_name = (kv.get("team") or "").strip()
        image_name = (kv.get("image") or "").strip()
        score_str = (kv.get("score") or "0").strip()
        vulns_hex = (kv.get("vulns") or "").strip()
        time_str = (kv.get("time") or "").strip()

        if not team_name or not image_name:
            return jsonify(error="Missing team or image in payload"), 400

        try:
            absolute_score = int(score_str)
        except ValueError:
            return jsonify(error="Invalid 'score' in payload"), 400

        try:
            ts = datetime.utcfromtimestamp(int(time_str)) if time_str else datetime.utcnow()
        except Exception:
            ts = datetime.utcnow()

        vulns_txt = _decrypt_inner_vulns(vulns_hex, ENGINE_SHARED_KEY)

        team = Team.query.filter_by(name=team_name).first() or get_or_create_team(team_name)
        image = VMImage.query.filter_by(name=image_name).first() or get_or_create_image(image_name)

        prior_total = _current_image_total(team.id, image.id)
        delta = absolute_score - prior_total
        if delta == 0:
            return jsonify(ok=True, delta=0, note="No score change"), 200

        reason = f"engine report ({image_name})"
        if vulns_txt:
            try:
                vparts = vulns_txt.split(DELIM)
                achieved = vparts[0] if len(vparts) > 0 else "?"
                total = vparts[1] if len(vparts) > 1 else "?"
                reason = f"engine report: {achieved}/{total} vulns"
            except Exception:
                pass

        ev = ImageScoreEvent(team_id=team.id, image_id=image.id, delta=delta,
                             reason=reason, timestamp=ts)
        db.session.add(ev)

        for u in team.users:
            u.image_scores = (u.image_scores or 0) + delta
            u.update_total_score()

        commit_with_retry()

        return jsonify(
            ok=True, team=team_name, image=image_name,
            prior_total=prior_total, reported=absolute_score,
            delta=delta, event_id=ev.id
        ), 200

    except Exception:
        current_app.logger.exception("engine_update crashed")
        return jsonify(error="internal error"), 500


# ---------------------------------------------------------------------------
# Background tasks
# ---------------------------------------------------------------------------
def background_uptime_scoring():
    while True:
        time.sleep(300)
        with app.app_context():
            try:
                apply_uptime_scoring()
            except Exception as e:
                current_app.logger.error(f"apply_uptime_scoring Missed: {e}")


def post_score_heartbeats():
    """Zero-delta heartbeat events so the time series stays continuous."""
    while True:
        time.sleep(HEARTBEAT_INTERVAL_SECONDS)
        try:
            with app.app_context():
                now = datetime.now(timezone.utc)

                subq = (
                    db.session.query(
                        ImageScoreEvent.team_id.label("team_id"),
                        ImageScoreEvent.image_id.label("image_id"),
                        func.max(ImageScoreEvent.timestamp).label("last_ts"),
                    )
                    .group_by(ImageScoreEvent.team_id, ImageScoreEvent.image_id)
                    .subquery()
                )

                stale_rows = db.session.query(subq.c.team_id, subq.c.image_id, subq.c.last_ts).all()

                created = 0
                for team_id, image_id, last_ts in stale_rows:
                    try:
                        last_dt = last_ts
                        if last_dt.tzinfo is None:
                            last_dt = last_dt.replace(tzinfo=timezone.utc)
                    except Exception:
                        continue

                    if (now - last_dt).total_seconds() >= HEARTBEAT_INTERVAL_SECONDS:
                        db.session.add(ImageScoreEvent(
                            team_id=team_id,
                            image_id=image_id,
                            delta=0,
                            reason="heartbeat (no score change)",
                            timestamp=now
                        ))
                        created += 1

                if created:
                    commit_with_retry()
                    current_app.logger.info(f"Heartbeat posted for {created} image streams.")
        except Exception as e:
            try:
                db.session.rollback()
            except Exception:
                pass
            current_app.logger.error(f"Heartbeat task failed: {e}")


if __name__ == '__main__':
    # threading.Thread(target=background_uptime_scoring, daemon=True).start()
    # threading.Thread(target=post_score_heartbeats, daemon=True).start()
    app.run(host='0.0.0.0', port=80, debug=True, threaded=True)
    # Production (waitress does NOT speak websockets — use gevent):
    #   gunicorn -k gevent --worker-connections 200 -b 0.0.0.0:80 app:app