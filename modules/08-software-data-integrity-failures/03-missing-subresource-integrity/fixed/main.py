# CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) — FIX.
# <script> tag'ine Subresource Integrity (SRI) eklenir: integrity="sha384-..." +
# crossorigin="anonymous". Tarayıcı, indirdiği script'in SHA-384 özetini bu değerle
# karşılaştırır; eşleşmezse script'i ÇALIŞTIRMAZ. Bu gerçek tarayıcı davranışıdır (W3C SRI).
"""
Modül 08 — Software or Data Integrity Failures
Senaryo 3: Missing Subresource Integrity / SRI (FIXED)

Tasarım: Harici script'in beklenen içeriğinin kriptografik özeti (SHA-384), HTML'e
`integrity` özniteliği olarak gömülür. Tarayıcı script'i indirdikten sonra özetini
hesaplar; gömülü değerle eşleşmezse script'i çalıştırmayı REDDEDER (ve konsola bir
SRI hatası yazar). Böylece CDN ele geçirilse bile değiştirilmiş kod çalışamaz.

- `GET /` → meşru lib.js, hash eşleşir → script çalışır.
- `GET /?tampered=true` → script src `/cdn/lib.js?tampered=true`'a döner ama integrity
  hâlâ MEŞRU sürümün hash'idir → hash uyuşmaz → tarayıcı script'i ÇALIŞTIRMAZ.

Bu DEFANGED DEĞİLDİR — gerçek tarayıcıda açıldığında native SRI korumasını gösterir.
lib.js meşru sürümü, vulnerable ile BAYT BAYT aynıdır (hash tutarlılığı için).

Çalıştırma: uvicorn main:app --port 8241
"""
# PORT: 8241
import base64
import hashlib

from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse

app = FastAPI()

PORT = 8241

# ÖNEMLİ: bu içerik vulnerable/main.py'deki LIB_JS_BENIGN ile BAYT BAYT AYNI olmalı,
# aksi halde hash tutmaz. (İki dosya bağımsız olduğundan burada da birebir tutuldu.)
LIB_JS_BENIGN = """// lib.js (meşru sürüm)
console.log('lib.js yüklendi (meşru sürüm)');
document.addEventListener('DOMContentLoaded', function () {
  var el = document.getElementById('sri-status');
  if (el) { el.textContent = 'lib.js yüklendi ✓ (meşru)'; el.style.color = 'green'; }
});
"""

LIB_JS_TAMPERED = """// lib.js (ELE GEÇİRİLMİŞ sürüm)
console.log('⚠️ CDN ELE GEÇİRİLDİ — bu normalde kötü amaçlı kod olurdu');
document.addEventListener('DOMContentLoaded', function () {
  var el = document.getElementById('sri-status');
  if (el) { el.textContent = '⚠️ CDN ELE GEÇİRİLDİ — değiştirilmiş script çalıştı!'; el.style.color = 'red'; }
});
"""


def _sri_hash(content: str) -> str:
    # SRI formatı: "sha384-" + base64(SHA-384 digest). Eşdeğeri:
    #   openssl dgst -sha384 -binary lib.js | openssl base64 -A
    digest = hashlib.sha384(content.encode("utf-8")).digest()
    return "sha384-" + base64.b64encode(digest).decode()


# Meşru lib.js'nin gerçek SRI hash'i — import anında hesaplanır (byte-for-byte doğru).
LIB_JS_SRI = _sri_hash(LIB_JS_BENIGN)


@app.get("/status")
def status():
    return {"status": "up", "scenario": "missing-subresource-integrity (fixed)", "sri_hash": LIB_JS_SRI}


@app.get("/cdn/lib.js")
def cdn_lib(tampered: bool = False):
    body = LIB_JS_TAMPERED if tampered else LIB_JS_BENIGN
    return Response(content=body, media_type="application/javascript")


@app.get("/", response_class=HTMLResponse)
def index(tampered: bool = False):
    # FIX: integrity (SHA-384) + crossorigin. Hash HER ZAMAN meşru sürümündür;
    # tampered içerik geldiğinde hash uyuşmaz ve tarayıcı script'i çalıştırmaz.
    src = f"http://127.0.0.1:{PORT}/cdn/lib.js" + ("?tampered=true" if tampered else "")
    return f"""<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <title>SRI Var — Fixed</title>
</head>
<body>
  <h1>Subresource Integrity VAR (Fixed)</h1>
  <p>Durum: <span id="sri-status">script bekleniyor…</span></p>
  <p><code>tampered={str(tampered).lower()}</code> — integrity hash'i meşru sürümündür.
     Tampered içerik gelirse tarayıcı hash uyuşmazlığı nedeniyle script'i çalıştırmaz
     (konsolda SRI hatası görünür, yukarıdaki durum "meşru" olmaz).</p>
  <!-- FIX: SHA-384 integrity + crossorigin=anonymous -->
  <script src="{src}" integrity="{LIB_JS_SRI}" crossorigin="anonymous"></script>
</body>
</html>"""
