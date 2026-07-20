# FIX (CWE-79): kullanıcı girdisi HTML'e gömülmeden önce html.escape ile kodlanır.
"""
Modül 05 — Injection
Senaryo 4: Reflected XSS (FIXED)

Remediation: `q` parametresi HTML gövdesine yazılmadan önce `html.escape()` ile çıktı
kodlamasından geçer. `<`, `>`, `&`, `"` gibi karakterler HTML varlıklarına (&lt; &gt; ...)
dönüştüğünden, `<script>` etiketi artık kod olarak yorumlanmaz; ekranda zararsız düz metin
olarak görünür. Kural: girdi çıktı bağlamına (HTML) uygun şekilde kodlanmalıdır.

Çalıştırma: uvicorn main:app --port 8151
"""
# PORT: 8151
import html

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()


@app.get("/status")
def status():
    return {"status": "up", "scenario": "reflected-xss-fixed"}


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    # FIX: Girdi, HTML bağlamına uygun şekilde escape edilir. Aynı <script> payload'ı
    # artık &lt;script&gt; olarak render edilir — çalışmaz, düz metin olarak görünür.
    safe_q = html.escape(q)
    return f"""<html>
  <body>
    <h1>Arama sonucu: {safe_q}</h1>
    <p>"{safe_q}" için sonuç bulunamadı.</p>
  </body>
</html>"""
