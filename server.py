import os, sys, json, time, threading
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from google import genai
from google.genai import types

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
BASE = os.path.dirname(os.path.abspath(__file__))
TZ = timezone(timedelta(hours=3))                  # توقيت الرياض
DAYS = ["الاثنين", "الثلاثاء", "الأربعاء", "الخميس", "الجمعة", "السبت", "الأحد"]

client = genai.Client(api_key=KEY)

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

def allowed(ip):
    now = time.time()
    today = datetime.now(TZ).strftime("%Y-%m-%d")
    with limits_lock:
        if day["d"] != today:
            day["d"], day["n"] = today, 0
        if day["n"] >= DAILY:
            return "وصلنا للحد اليومي للاستخدام. جرب بكرة إن شاء الله."
        q = hits[ip]
        while q and now - q[0] > WINDOW:
            q.popleft()
        if len(q) >= PER_IP:
            return "كلمتني كتير في وقت قصير. استنى شوية وجرب تاني."
        q.append(now)
        day["n"] += 1
        if len(hits) > 5000:
            for k in [k for k, v in hits.items() if not v]:
                del hits[k]
        return None

# ---------- جارفيس ----------
def system_prompt():
    n = datetime.now(TZ)
    return (
        "أنت جارفيس، مساعد ذكي شخصي. رد بنفس لغة المستخدم وبالعامية المصرية، باختصار ومباشرة. "
        "اليوم " + DAYS[n.weekday()] + " " + n.strftime("%Y-%m-%d") + " والساعة " + n.strftime("%H:%M") +
        " بتوقيت الرياض. لأي سؤال عن معلومة ممكن تتغير (تواريخ، أخبار، أسعار، طقس، مواقيت) "
        "ابحث في الإنترنت وجاوب بدقة، ولا تعتمد على ذاكرتك. "
        "مطورك وصانعك هو سيف إسلام، ولو حد سألك عن صانعك قول كده وامدحه بشكل لطيف."
    )

def save(hist, text):
    hist.append(types.Content(role="model", parts=[types.Part(text=text)]))
    while len(hist) > 20:
        del hist[:2]

def stream_reply(hist, text):
    hist.append(types.Content(role="user", parts=[types.Part(text=text)]))
    last = ""
    for model in MODELS:
        for use_search in (True, False):
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
                if use_search and ("400" in last or "INVALID_ARGUMENT" in last):
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

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/healthz":
            return self.reply(200, "ok")
        item = STATIC.get(path)
        if not item:
            return self.reply(404, "not found")
        try:
            with open(os.path.join(BASE, item[0]), "rb") as f:
                self.reply(200, f.read(), item[1])
        except FileNotFoundError:
            self.reply(404, "not found")

    def do_POST(self):
        try:
            n = min(int(self.headers.get("Content-Length", 0)), 4096)
            data = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self.reply(400, "طلب غير صالح")
        sess = get_session(data.get("sid", ""))
        if self.path == "/reset":
            with sess["lock"]:
                sess["h"].clear()
            return self.reply(200, "ok")
        if self.path != "/chat":
            return self.reply(404, "not found")
        text = str(data.get("text", "")).strip()[:MAX_LEN]
        if not text:
            return self.reply(400, "اكتب رسالة")
        blocked = allowed(self.client_ip())
        if blocked:
            return self.reply(429, blocked)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        try:
            with sess["lock"]:
                for part in stream_reply(sess["h"], text):
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
