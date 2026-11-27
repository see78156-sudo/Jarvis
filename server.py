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
MAX_HISTORY = 20                                   # آخر كام رسالة نبعتها كسياق
MAX_HIST_CHARS = 4000
ERR_MARK = "\u200b\u2060\u200b"                       # علامة مخفية بتبين إن الرد فيه خطأ
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
    "/download": ("download.html", "text/html; charset=utf-8"),
    "/get": ("download.html", "text/html; charset=utf-8"),
    "/qr.png": ("qr.png", "image/png"),
    "/jarvis.apk": ("jarvis.apk", "application/vnd.android.package-archive"),
}

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

def build_history(raw):
    """المحادثة السابقة بتيجي من الصفحة (نص بس)، فالسيرفر مش بيحفظ حاجة."""
    out = []
    if not isinstance(raw, list):
        return out
    for m in raw[-MAX_HISTORY:]:
        if not isinstance(m, dict):
            continue
        role = "model" if m.get("role") in ("model", "assistant") else "user"
        txt = str(m.get("text", "")).strip()[:MAX_HIST_CHARS]
        if txt:
            out.append(types.Content(role=role, parts=[types.Part(text=txt)]))
    while out and out[0].role != "user":
        out.pop(0)
    return out

# ---------- جارفيس ----------
BIO = """
معلومات عن مطورك سيف إسلام. استخدمها لما حد يسأل: مين سيف؟ مين المطور؟ مين صنعك؟
- اسمه سيف إسلام، عنده 17 سنة، وطالب في تانية ثانوي.
- هو صاحب فكرة جارفيس وبناه بنفسه، وإلهامه كان مساعد جارفيس بتاع توني ستارك في الأفلام.
- من الشباب الصغيرين اللي بدأوا بدري في بناء برامج الذكاء الاصطناعي في الوطن العربي.
- عمل لجارفيس موقع عام وتطبيق أندرويد ونسخة تتثبت على الآيفون، وضاف له الكاميرا ورفع الصور والملفات وتسجيل الدخول وحفظ المحادثات.
- كان بيتعلم وهو بيبني: واجه مشاكل كتير (مفاتيح اترفضت، وموديلات مشغولة، ونشر على استضافة) وما وقفش، وكمل لحد ما اشتغل.
- صفاته: مصمم وصبور وبيحب يجرب ويتعلم وطموحه كبير.
لو حد سأل عنه، رد برد طويل ومفصّل (10 سطور أو أكتر) بأسلوب دافئ ومحترم ومادح، وما تخترعش تفاصيل مش مكتوبة هنا (زي اسم المدرسة أو العنوان أو العيلة أو رقم التليفون).
"""

VOICE_STYLE = (
    "أنت الآن في محادثة صوتية مباشرة: رد بالعربية الفصحى المبسطة (إلا لو كلمك المستخدم بالإنجليزية فرد بها)، "
    "بنبرة هادئة واثقة ومهنية مثل جارفيس، وناده «سيدي» أحياناً، ويمكنك أن تبدأ أو تنهي الرد بها. اجعل الرد من جملتين إلى ثلاث جمل قصيرة، "
    "ومن غير رموز أو نقاط أو قوائم أو إيموجي أو روابط، وتجنب الأرقام الطويلة. "
    "استثناء: لو سُئلت عن سيف إسلام فرد بالطول المطلوب وبالفصحى أيضاً."
)

def system_prompt(voice=False):
    n = datetime.now(TZ)
    return (
        "أنت جارفيس، مساعد ذكي شخصي. إذا كلّمك المستخدم بالعربية فرد دائماً بالعربية الفصحى المبسطة السليمة (وليس بالعامية أو اللهجة المصرية)، بنبرة مهذبة واثقة، وناده «سيدي» عند اللزوم، وإذا كلّمك بلغة أخرى فرد بها، باختصار ومباشرة. "
        "اليوم " + DAYS[n.weekday()] + " " + n.strftime("%Y-%m-%d") + " والساعة " + n.strftime("%H:%M") +
        " بتوقيت الرياض. لأي سؤال عن معلومة ممكن تتغير (تواريخ، أخبار، أسعار، طقس، مواقيت) "
        "ابحث في الإنترنت وجاوب بدقة، ولا تعتمد على ذاكرتك. "
        "لو المستخدم أرفق صورة أو ملف، حلله بعناية وجاوب على سؤاله عنه. "
        "مطورك وصانعك هو سيف إسلام، ولو حد سألك عن صانعك قول كده وامدحه بشكل لطيف. " + BIO
        + (" " + VOICE_STYLE if voice else "")
    )

def stream_reply(history, parts, voice=False):
    contents = history + [types.Content(role="user", parts=parts)]
    last = ""
    for model in MODELS:
        for use_search in SEARCH_MODES:
            tools = [types.Tool(google_search=types.GoogleSearch())] if use_search else None
            cfg = types.GenerateContentConfig(system_instruction=system_prompt(voice), tools=tools)
            got = ""
            try:
                for chunk in client.models.generate_content_stream(model=model, contents=contents, config=cfg):
                    if chunk.text:
                        got += chunk.text
                        yield chunk.text
                if got:
                    return
                last = "رد فاضي"
            except Exception as e:
                last = str(e)
                if got:
                    yield "\n[الرد انقطع]"
                    return
                if use_search and len(SEARCH_MODES) > 1 and any(c in last for c in ("400", "INVALID_ARGUMENT", "429", "RESOURCE_EXHAUSTED")):
                    continue
                break
    print("Gemini error:", last, flush=True)
    raise RuntimeError("جارفيس مشغول دلوقتي. جرب بعد شوية.")

# ---------- السيرفر ----------
class H(BaseHTTPRequestHandler):
    def client_ip(self):
        fwd = self.headers.get("X-Forwarded-For", "")
        return (fwd.split(",")[0].strip() if fwd else self.client_address[0]) or "unknown"

    def reply(self, code, body, ctype="text/plain; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
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
                   "projectId": FIREBASE_PROJECT_ID if AUTH_ON else "", "requireVerified": REQUIRE_VERIFIED,
                   "apk": os.path.exists(os.path.join(BASE, "jarvis.apk"))}
            return self.reply(200, json.dumps(cfg), "application/json; charset=utf-8")
        item = STATIC.get(path)
        if not item:
            return self.reply(404, "not found")
        try:
            extra = {"Content-Disposition": 'attachment; filename="Jarvis-AI.apk"'} if path == "/jarvis.apk" else None
            with open(os.path.join(BASE, item[0]), "rb") as f:
                self.reply(200, f.read(), item[1], extra)
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
        if self.path == "/reset":
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
        history = build_history(data.get("history"))
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        try:
            for part in stream_reply(history, parts, bool(data.get("voice"))):
                self.wfile.write(part.encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            try:
                self.wfile.write(("\n" + ERR_MARK + "⚠️ " + str(e)).encode("utf-8"))
            except Exception:
                pass

    def log_message(self, *a):
        pass

if __name__ == "__main__":
    print("Jarvis running on port", PORT, flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
