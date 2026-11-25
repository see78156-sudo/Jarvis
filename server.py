import os, sys, json, time, threading, base64
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from google import genai
from google.genai import types
from google.oauth2 import id_token as g_id_token
from google.auth.transport import requests as g_requests

KEY = os.environ.get("GEMINI_API_KEY", "").strip()
if not KEY:
    sys.exit("GEMINI_API_KEY is not set")

PORT = int(os.environ.get("PORT", "8080"))
MODELS = [m.strip() for m in os.environ.get(
    "MODELS", "gemini-3.7-flash,gemini-3.8-flash,gemini-3.6-flash,gemini-3.5-flash-lite"
).split(",") if m.strip()]
PER_IP = int(os.environ.get("PER_IP", "20"))      # رسائل لكل شخص
WINDOW = int(os.environ.get("WINDOW", "600"))     # خلال كام ثانية (600 = 10 دقايق)
DAILY = int(os.environ.get("DAILY", "800"))       # الحد اليومي لكل الناس
MAX_LEN = 500                                      # أقصى طول للرسالة
MAX_BODY = int(os.environ.get("MAX_BODY_MB", "8")) * 1024 * 1024   # أقصى حجم للطلب
MAX_FILES = 3                                      # أقصى عدد مرفقات في الرسالة
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_TEXT_CHARS = 60000
BASE = os.path.dirname(os.path.abspath(__file__))
TZ = timezone(timedelta(hours=3))                  # توقيت الرياض
DAYS = ["الاثنين", "الثلاثاء", "الأربعاء", "الخميس", "الجمعة", "السبت", "الأحد"]
SEARCH_MODES = (True, False) if os.environ.get("USE_SEARCH", "1") != "0" else (False,)

client = genai.Client(api_key=KEY)

# ---------- تسجيل الدخول (Firebase Authentication) ----------
FIREBASE_PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID", "").strip()
FIREBASE_API_KEY = os.environ.get("FIREBASE_API_KEY", "").strip()
AUTH_ON = bool(FIREBASE_PROJECT_ID and FIREBASE_API_KEY)   # لو مش متظبطين، التطبيق يفضل مفتوح زي ما كان
REQUIRE_VERIFIED = os.environ.get("REQUIRE_VERIFIED", "0") == "1"
_auth_request = g_requests.Request()
tok_cache = {}
tok_lock = threading.Lock()

def verify_token(token):
    if not token or len(token) > 4096:
        return None
    now = time.time()
    with tok_lock:
        c = tok_cache.get(token)
        if c and c[1] > now:
            return c[0]
    try:
        claims = g_id_token.verify_firebase_token(token, _auth_request, audience=FIREBASE_PROJECT_ID)
    except Exception as e:
        print("auth failed:", type(e).__name__, flush=True)
        return None
    if (not claims or not claims.get("sub")
            or claims.get("iss") != "https://securetoken.google.com/" + FIREBASE_PROJECT_ID):
        return None
    with tok_lock:
        if len(tok_cache) > 2000:
            tok_cache.clear()
        tok_cache[token] = (claims, min(float(claims.get("exp", 0)), now + 300))
    return claims

STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/manifest.json": ("manifest.json", "application/manifest+json; charset=utf-8"),
    "/sw.js": ("sw.js", "application/javascript; charset=utf-8"),
    "/icon-192.png": ("icon-192.png", "image/png"),
    "/icon-512.png": ("icon-512.png", "image/png"),
    "/icon-maskable-512.png": ("icon-maskable-512.png", "image/png"),
}

# ---------- الجلسات (كل شخص له محادثته) ----------
sessions = {}
sessions_lock = threading.Lock()

def get_session(sid):
    sid = "".join(ch for ch in str(sid) if ch.isalnum() or ch in "-_")[:64] or "anon"
    now = time.time()
    with sessions_lock:
        if len(sessions) > 300:
            for k in sorted(sessions, key=lambda k: sessions[k]["t"])[:100]:
                del sessions[k]
        s = sessions.setdefault(sid, {"h": [], "t": now, "lock": threading.Lock()})
        s["t"] = now
        return s

# ---------- حدود الاستخدام ----------
hits = defaultdict(deque)
day = {"d": "", "n": 0}
limits_lock = threading.Lock()

def allowed(ip, cost=1):
    now = time.time()
    today = datetime.now(TZ).strftime("%Y-%m-%d")
    with limits_lock:
        if day["d"] != today:
            day["d"], day["n"] = today, 0
        if day["n"] + cost > DAILY:
            return "وصلنا للحد اليومي للاستخدام. جرب بكرة إن شاء الله."
        q = hits[ip]
        while q and now - q[0] > WINDOW:
            q.popleft()
        if len(q) + cost > PER_IP:
            return "كلمتني كتير في وقت قصير. استنى شوية وجرب تاني."
        for _ in range(cost):
            q.append(now)
        day["n"] += cost
        if len(hits) > 5000:
            for k in [k for k, v in hits.items() if not v]:
                del hits[k]
        return None

# ---------- المرفقات ----------
def sniff(raw):
    if raw[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if raw[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return "image/webp"
    if raw[:5] == b"%PDF-":
        return "application/pdf"
    return None

def build_parts(text, attachments):
    parts = []
    if not isinstance(attachments, list):
        attachments = []
    for a in attachments[:MAX_FILES]:
        if not isinstance(a, dict):
            continue
        kind = a.get("type")
        name = str(a.get("name", "file"))[:80]
        data = a.get("data", "")
        if kind == "text":
            parts.append(types.Part(text="[ملف نصي: %s]\n%s" % (name, str(data)[:MAX_TEXT_CHARS])))
        elif kind in ("image", "pdf"):
            try:
                raw = base64.b64decode(data)
            except Exception:
                continue
            if not raw or len(raw) > MAX_FILE_BYTES:
                continue
            mime = sniff(raw)
            if not mime or (kind == "pdf") != (mime == "application/pdf"):
                continue
            parts.append(types.Part.from_bytes(data=raw, mime_type=mime))
    if not text and parts:
        text = "اشرحلي المرفقات دي باختصار وقولي إيه المهم فيها."
    parts.append(types.Part(text=text))
    return parts

def has_media(parts):
    return any(getattr(p, "inline_data", None) for p in parts)

def strip_old_media(hist):
    # نشيل الصور والـ PDF القديمة من المحادثة عشان الذاكرة ما تتملاش
    for i, c in enumerate(hist):
        if any(getattr(p, "inline_data", None) for p in c.parts):
            new = [types.Part(text="[مرفق من رسالة سابقة]") if getattr(p, "inline_data", None) else p
                   for p in c.parts]
            hist[i] = types.Content(role=c.role, parts=new)

# ---------- جارفيس ----------
def system_prompt():
    n = datetime.now(TZ)
    return (
        "أنت جارفيس، مساعد ذكي شخصي. رد بنفس لغة المستخدم وبالعامية المصرية، باختصار ومباشرة. "
        "اليوم " + DAYS[n.weekday()] + " " + n.strftime("%Y-%m-%d") + " والساعة " + n.strftime("%H:%M") +
        " بتوقيت الرياض. لأي سؤال عن معلومة ممكن تتغير (تواريخ، أخبار، أسعار، طقس، مواقيت) "
        "ابحث في الإنترنت وجاوب بدقة، ولا تعتمد على ذاكرتك. "
        "لو المستخدم أرفق صورة أو ملف، حلله بعناية وجاوب على سؤاله عنه. "
        "مطورك وصانعك هو سيف إسلام، ولو حد سألك عن صانعك قول كده وامدحه بشكل لطيف."
    )

def save(hist, text):
    hist.append(types.Content(role="model", parts=[types.Part(text=text)]))
    while len(hist) > 20:
        del hist[:2]

def stream_reply(hist, parts):
    if has_media(parts):
        strip_old_media(hist)
    hist.append(types.Content(role="user", parts=parts))
    last = ""
    for model in MODELS:
        for use_search in SEARCH_MODES:
            tools = [types.Tool(google_search=types.GoogleSearch())] if use_search else None
            cfg = types.GenerateContentConfig(system_instruction=system_prompt(), tools=tools)
            got = ""
            try:
                for chunk in client.models.generate_content_stream(model=model, contents=hist, config=cfg):
                    if chunk.text:
                        got += chunk.text
                        yield chunk.text
                if got:
                    save(hist, got)
                    return
                last = "رد فاضي"
            except Exception as e:
                last = str(e)
                if got:
                    save(hist, got)
                    yield "\n[الرد انقطع]"
                    return
                if use_search and len(SEARCH_MODES) > 1 and any(c in last for c in ("400", "INVALID_ARGUMENT", "429", "RESOURCE_EXHAUSTED")):
                    continue
                break
    hist.pop()
    print("Gemini error:", last, flush=True)
    raise RuntimeError("جارفيس مشغول دلوقتي. جرب بعد شوية.")

# ---------- السيرفر ----------
class H(BaseHTTPRequestHandler):
    def client_ip(self):
        fwd = self.headers.get("X-Forwarded-For", "")
        return (fwd.split(",")[0].strip() if fwd else self.client_address[0]) or "unknown"

    def reply(self, code, body, ctype="text/plain; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authenticate(self):
        if not AUTH_ON:
            return None, None, None
        h = self.headers.get("Authorization", "")
        if not h.startswith("Bearer "):
            return None, 401, "سجّل دخولك الأول."
        claims = verify_token(h[7:].strip())
        if not claims:
            return None, 401, "انتهت الجلسة. سجّل دخولك تاني."
        if REQUIRE_VERIFIED and not claims.get("email_verified"):
            return None, 403, "فعّل الإيميل الأول من الرسالة اللي اتبعتتلك."
        return claims["sub"], None, None

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/healthz":
            return self.reply(200, "ok")
        if path == "/config.json":
            cfg = {"authEnabled": AUTH_ON, "apiKey": FIREBASE_API_KEY if AUTH_ON else "",
                   "requireVerified": REQUIRE_VERIFIED}
            return self.reply(200, json.dumps(cfg), "application/json; charset=utf-8")
        item = STATIC.get(path)
        if not item:
            return self.reply(404, "not found")
        try:
            with open(os.path.join(BASE, item[0]), "rb") as f:
                self.reply(200, f.read(), item[1])
        except FileNotFoundError:
            self.reply(404, "not found")

    def do_POST(self):
        uid, code, msg = self.authenticate()
        if msg:
            self.close_connection = True
            return self.reply(code, msg)
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return self.reply(400, "طلب غير صالح")
        if n > MAX_BODY:
            self.close_connection = True
            return self.reply(413, "الملفات كبيرة أوي. صغّرها وجرب تاني.")
        try:
            data = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self.reply(400, "طلب غير صالح")
        sess = get_session(("u_" + uid) if uid else data.get("sid", ""))
        if self.path == "/reset":
            with sess["lock"]:
                sess["h"].clear()
            return self.reply(200, "ok")
        if self.path != "/chat":
            return self.reply(404, "not found")
        text = str(data.get("text", "")).strip()[:MAX_LEN]
        attachments = data.get("attachments") or []
        if not text and not attachments:
            return self.reply(400, "اكتب رسالة")
        blocked = allowed(uid or self.client_ip(), 2 if attachments else 1)
        if blocked:
            return self.reply(429, blocked)
        parts = build_parts(text, attachments)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        try:
            with sess["lock"]:
                for part in stream_reply(sess["h"], parts):
                    self.wfile.write(part.encode("utf-8"))
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            try:
                self.wfile.write(("\n⚠️ " + str(e)).encode("utf-8"))
            except Exception:
                pass

    def log_message(self, *a):
        pass

if __name__ == "__main__":
    print("Jarvis running on port", PORT, flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
