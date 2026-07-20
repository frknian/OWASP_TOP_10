"""
Modül 02 — Security Misconfiguration
Senaryo 1: Forgotten Sample App / Default Credentials (VULNERABLE)

Zafiyet: Uygulamanın ilk kurulumundan kalma bir "kurulum / örnek yönetim paneli"
(`/sample-admin`) production'a taşınmış ve unutulmuş. Panel, sabit kodlanmış
"admin"/"admin" varsayılan kimlik bilgisiyle korunuyor. Doğru kimlik girildiğinde
sunucuya dair keşif (reconnaissance) değeri yüksek "system info" bilgisi (Python/
FastAPI sürümü, OS) sızdırıyor.

Bu, gerçek kullanıcı tablosundan (users) tamamen bağımsız, kendi başına bir
misconfiguration örneğidir — kök neden zayıf parola değil, bu endpoint'in production'da
hiç bulunmaması gerektiğidir.

Çalıştırma: uvicorn main:app --port 8010
"""
# PORT: 8010
import platform

import fastapi
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI()


@app.get("/")
def index():
    # "Gerçek" uygulamanın normal yüzü — asıl ürün burada yaşıyor.
    return {"app": "Acme Widgets API", "status": "running"}


# --- Unutulmuş kurulum paneli (production'a sızmış olmamalıydı) --------------

SAMPLE_ADMIN_LOGIN_FORM = """
<!doctype html>
<title>Setup Panel</title>
<h2>Acme Setup / Sample Admin Panel</h2>
<form method="post" action="/sample-admin">
  <input name="username" placeholder="username">
  <input name="password" type="password" placeholder="password">
  <button type="submit">Login</button>
</form>
<p>Default credentials: admin / admin</p>
"""


@app.get("/sample-admin", response_class=HTMLResponse)
def sample_admin_form():
    # Kurulum panelinin giriş formu — herkese açık şekilde erişilebilir durumda.
    return SAMPLE_ADMIN_LOGIN_FORM


@app.post("/sample-admin")
def sample_admin_login(request: Request, username: str = Form(...), password: str = Form(...)):
    # ZAFIYET: Kimlik kontrolü, kaynak koda gömülü varsayılan "admin"/"admin" ile yapılıyor.
    # Bu kimlik bilgileri kurulum aracının fabrika ayarıdır; kimse değiştirmemiş ve panel
    # de production'dan kaldırılmamış. Saldırgan bu iyi bilinen varsayılanı deneyerek
    # (PR:N — hiçbir önceden ayrıcalık gerekmeden) panele girebilir.
    if username == "admin" and password == "admin":
        # Panel, saldırgana keşif değeri yüksek "system info" döndürüyor. Tek başına
        # zararsız görünen bu bilgiler (sürüm numaraları), bilinen CVE'lerle eşleştirilerek
        # hedefli bir saldırının ilk adımını (fingerprinting) oluşturur.
        return JSONResponse(
            {
                "message": "Welcome to the Acme setup panel",
                "system_info": {
                    "python_version": platform.python_version(),
                    "fastapi_version": fastapi.__version__,
                    "os": f"{platform.system()} {platform.release()}",
                    "hostname": platform.node(),
                },
            }
        )
    return JSONResponse({"detail": "Invalid credentials"}, status_code=401)
