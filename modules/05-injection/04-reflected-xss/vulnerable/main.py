# CWE-79 (Cross-site Scripting): kullanıcı girdisi HTML'e escape edilmeden gömülür.
"""
Modül 05 — Injection
Senaryo 4: Reflected XSS (VULNERABLE)

Zafiyet: `GET /search?q=...` bir HTML sayfası döndürür ve `q` parametresini HİÇBİR
çıktı kodlaması (escaping) yapmadan doğrudan HTML gövdesine gömer. Girdi HTML olarak
yorumlandığından, içindeki `<script>` etiketi kurbanın tarayıcısında çalışır.

Zararsız PoC (yalnızca gösterim): `<script>document.title='XSS-Demo'</script>`
— sayfa başlığını değiştirir; gerçek bir kötü amaçlı yük içermez.

Çalıştırma: uvicorn main:app --port 8150
"""
# PORT: 8150
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()


@app.get("/status")
def status():
    return {"status": "up", "scenario": "reflected-xss"}


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    # ZAFIYET: q kullanıcı girdisi olduğu halde escape edilmeden HTML'e gömülüyor.
    # <script>...</script> gönderilirse tarayıcı bunu kod olarak çalıştırır (reflected XSS).
    return f"""<html>
  <body>
    <h1>Arama sonucu: {q}</h1>
    <p>"{q}" için sonuç bulunamadı.</p>
  </body>
</html>"""
