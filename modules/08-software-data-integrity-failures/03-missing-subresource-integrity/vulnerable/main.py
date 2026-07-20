# CWE-829 (Inclusion of Functionality from Untrusted Control Sphere): HTML sayfası,
# harici bir kaynaktan (CDN) yüklediği script'in bütünlüğünü hiçbir şekilde doğrulamaz.
# CDN ele geçirilir/script değiştirilirse, tarayıcı değiştirilmiş kodu sorgusuz çalıştırır.
"""
Modül 08 — Software or Data Integrity Failures
Senaryo 3: Missing Subresource Integrity / SRI (VULNERABLE)

Bağlam: Sayfa, bir "CDN"den (bu labda kendi /cdn/lib.js endpoint'imiz — dış bağlantı yok)
bir JavaScript kütüphanesi yükler. <script> tag'inde HİÇ `integrity`/`crossorigin`
özniteliği yoktur.

Zafiyet: Tarayıcının, yüklenen script'in beklenen içerikle aynı olup olmadığını
doğrulama imkânı yoktur. CDN ele geçirilir (veya MITM ile içerik değiştirilirse),
tarayıcı değiştirilmiş kodu sayfanın tam yetkisiyle çalıştırır (tedarik zinciri saldırısı).

Test için: `GET /?tampered=true` → sayfa script'i `/cdn/lib.js?tampered=true`'dan yükler
("ele geçirilmiş CDN" simülasyonu). SRI olmadığı için değiştirilmiş script yine çalışır.

Çalıştırma: uvicorn main:app --port 8240
"""
# PORT: 8240
from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse

app = FastAPI()

PORT = 8240

# Meşru kütüphane (zararsız): sayfadaki durum kutusunu günceller.
LIB_JS_BENIGN = """// lib.js (meşru sürüm)
console.log('lib.js yüklendi (meşru sürüm)');
document.addEventListener('DOMContentLoaded', function () {
  var el = document.getElementById('sri-status');
  if (el) { el.textContent = 'lib.js yüklendi ✓ (meşru)'; el.style.color = 'green'; }
});
"""

# "Ele geçirilmiş" kütüphane (yine zararsız — sadece gösterim). Gerçek saldırıda burada
# çerez çalma / keylogger / kripto madenci gibi kötü amaçlı kod olurdu.
LIB_JS_TAMPERED = """// lib.js (ELE GEÇİRİLMİŞ sürüm)
console.log('⚠️ CDN ELE GEÇİRİLDİ — bu normalde kötü amaçlı kod olurdu');
document.addEventListener('DOMContentLoaded', function () {
  var el = document.getElementById('sri-status');
  if (el) { el.textContent = '⚠️ CDN ELE GEÇİRİLDİ — değiştirilmiş script çalıştı!'; el.style.color = 'red'; }
});
"""


@app.get("/status")
def status():
    return {"status": "up", "scenario": "missing-subresource-integrity"}


@app.get("/cdn/lib.js")
def cdn_lib(tampered: bool = False):
    # "Sahte CDN" endpoint'i. tampered=true → ele geçirilmiş içerik döner.
    body = LIB_JS_TAMPERED if tampered else LIB_JS_BENIGN
    return Response(content=body, media_type="application/javascript")


@app.get("/", response_class=HTMLResponse)
def index(tampered: bool = False):
    # ZAFIYET: <script> tag'inde integrity/crossorigin YOK — bütünlük doğrulaması yapılmaz.
    src = f"http://127.0.0.1:{PORT}/cdn/lib.js" + ("?tampered=true" if tampered else "")
    return f"""<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <title>SRI Yok — Vulnerable</title>
</head>
<body>
  <h1>Subresource Integrity YOK (Vulnerable)</h1>
  <p>Durum: <span id="sri-status">script bekleniyor…</span></p>
  <p><code>tampered={str(tampered).lower()}</code> — SRI olmadığından hangi içerik gelirse çalışır.</p>
  <!-- ZAFIYET: integrity ve crossorigin öznitelikleri YOK -->
  <script src="{src}"></script>
</body>
</html>"""
