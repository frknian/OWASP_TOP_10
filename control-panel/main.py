"""
Web Security Lab — Control Panel (Faz 1: Launcher)

modules/ altındaki bilinçli-zafiyetli senaryoları BAŞLATIP DURDURAN ayrı bir iç araç.
Senaryo kodlarına hiç dokunmaz; her main.py'nin en üstündeki `# PORT: XXXX` işaretini
okuyarak hangi uygulamanın hangi portta çalışacağını öğrenir ve her birini kendi
venv'iyle ayrı bir subprocess olarak ayağa kaldırır.

Çalıştırma:
    cd control-panel
    python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
    ./venv/bin/uvicorn main:app --port 9000
"""
import asyncio
import base64
import os
import re
import socket
import subprocess
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# control-panel/ bir üst dizinde modules/ var.
BASE_DIR = Path(__file__).resolve().parent
MODULES_DIR = BASE_DIR.parent / "modules"

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
# Python 3.14 + Jinja2 bug workaround (pallets/jinja#2180): LRUCache, cache key olarak
# hashlenemez bir dict içeren tuple üretiyor → template cache'i kapatıyoruz. Bu panel
# için performans etkisi yok (sık render edilmiyor).
templates.env.cache = None

PORT_RE = re.compile(r"^# PORT:\s*(\d{4})", re.MULTILINE)
VARIANTS = ("vulnerable", "fixed")

# Panel tarafından başlatılan alt süreçler: port -> Popen
_processes: dict[int, subprocess.Popen] = {}

# Taranan senaryolar (bellekte). Yapı:
# [{modul, senaryo, vulnerable_port, vulnerable_path, fixed_port, fixed_path}, ...]
_scenarios: list[dict] = []

# Modül 04 fixed S2/S3 fail-secure: ENCRYPTION_KEY yoksa başlamayı reddederler.
# Panel, başlattığı HER alt sürece bu anahtarı enjekte eder ki bu senaryolar da
# panelden çalıştırılabilsin. (Geçerli Fernet formatı: 32 rastgele bayt -> urlsafe b64.)
_ENCRYPTION_KEY = base64.urlsafe_b64encode(os.urandom(32)).decode()


def _read_port(main_py: Path) -> int | None:
    try:
        m = PORT_RE.search(main_py.read_text(encoding="utf-8"))
        return int(m.group(1)) if m else None
    except OSError:
        return None


def scan_modules() -> list[dict]:
    """modules/ altını tarar, her senaryonun vulnerable/fixed portlarını çıkarır."""
    found: list[dict] = []
    if not MODULES_DIR.is_dir():
        return found
    for modul_dir in sorted(MODULES_DIR.glob("[0-9][0-9]-*")):
        if not modul_dir.is_dir():
            continue
        for senaryo_dir in sorted(modul_dir.glob("[0-9][0-9]-*")):
            if not senaryo_dir.is_dir():
                continue
            entry = {"modul": modul_dir.name, "senaryo": senaryo_dir.name}
            has_any = False
            for variant in VARIANTS:
                main_py = senaryo_dir / variant / "main.py"
                if main_py.is_file():
                    entry[f"{variant}_port"] = _read_port(main_py)
                    entry[f"{variant}_path"] = str(main_py.parent)
                    has_any = True
                else:
                    entry[f"{variant}_port"] = None
                    entry[f"{variant}_path"] = None
            if has_any:
                found.append(entry)
    return found


def _refresh() -> None:
    global _scenarios
    _scenarios = scan_modules()


def _known_ports() -> list[int]:
    ports = []
    for s in _scenarios:
        for variant in VARIANTS:
            p = s.get(f"{variant}_port")
            if p:
                ports.append(p)
    return ports


def _is_listening(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.25)
        return sock.connect_ex((host, port)) == 0


def _find_scenario(modul: str, senaryo: str) -> dict | None:
    for s in _scenarios:
        if s["modul"] == modul and s["senaryo"] == senaryo:
            return s
    return None


def _lsof_kill(port: int) -> bool:
    """Panel kaydında olmayan (orphan) süreçleri porttan bulup öldürür."""
    try:
        out = subprocess.run(
            ["lsof", "-ti", f"tcp:{port}"], capture_output=True, text=True, timeout=5
        )
        pids = [p for p in out.stdout.split() if p]
        killed = False
        for pid in pids:
            subprocess.run(["kill", pid], timeout=5)
            killed = True
        return killed
    except (OSError, subprocess.SubprocessError):
        return False


app = FastAPI(title="Web Security Lab — Control Panel")

# Vite dev server (5173) farklı bir origin'den istek attığında, cookie'li (credentials)
# proxy çağrılarının çalışması için CORS gerekli. allow_credentials=True ile birlikte
# origin'ler açıkça listelenmeli ("*" credentials'la çalışmaz).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    _refresh()


@app.get("/")
def index():
    """Ana giriş noktası: React arayüzüne (yeni landing sayfası) yönlendirir.

    Arayüz, frontend/dist build'i /app mount'u altında servis edilir. Teknik
    launcher (manuel başlat/durdur tablosu) /launcher adresine taşındı."""
    return RedirectResponse(url="/app/")


@app.get("/launcher")
def dashboard(request: Request):
    """Teknik launcher: 34 senaryonun vulnerable/fixed sürümlerini manuel başlat/durdur."""
    return templates.TemplateResponse(
        request, "dashboard.html", {"scenarios": _scenarios}
    )


@app.get("/api/scan")
def api_scan():
    _refresh()
    return {"count": len(_scenarios), "scenarios": _scenarios}


@app.get("/api/status")
def api_status():
    """Bilinen tüm portların anlık durumu: {port: bool}."""
    return {str(p): _is_listening(p) for p in _known_ports()}


def _launch_backend(scen: dict, variant: str) -> tuple[dict | None, tuple[str, int] | None]:
    """Senaryonun ilgili sürümünü başlatır. (sonuç, hata) döner; hata (mesaj, status)."""
    port = scen.get(f"{variant}_port")
    workdir = scen.get(f"{variant}_path")
    if not port or not workdir:
        return None, (f"{variant} için port/yol yok", 404)

    if _is_listening(port):
        return {"status": "already_running", "port": port}, None

    uvicorn_bin = Path(workdir) / "venv" / "bin" / "uvicorn"
    if not uvicorn_bin.exists():
        return None, (
            f"venv bulunamadı ({workdir}). Önce ilgili modülde setup_venvs.sh çalıştırın.",
            400,
        )

    env = {**os.environ, "ENCRYPTION_KEY": _ENCRYPTION_KEY}
    proc = subprocess.Popen(
        [str(uvicorn_bin), "main:app", "--port", str(port)],
        cwd=workdir,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    _processes[port] = proc
    return {"status": "started", "port": port, "pid": proc.pid}, None


@app.post("/api/start/{variant}/{modul}/{senaryo}")
def api_start(variant: str, modul: str, senaryo: str):
    if variant not in VARIANTS:
        return JSONResponse({"error": f"Geçersiz variant: {variant}"}, status_code=400)
    scen = _find_scenario(modul, senaryo)
    if scen is None:
        return JSONResponse({"error": "Senaryo bulunamadı"}, status_code=404)
    result, err = _launch_backend(scen, variant)
    if err:
        return JSONResponse({"error": err[0]}, status_code=err[1])
    return result


@app.post("/api/stop/{variant}/{modul}/{senaryo}")
def api_stop(variant: str, modul: str, senaryo: str):
    if variant not in VARIANTS:
        return JSONResponse({"error": f"Geçersiz variant: {variant}"}, status_code=400)
    scen = _find_scenario(modul, senaryo)
    if scen is None:
        return JSONResponse({"error": "Senaryo bulunamadı"}, status_code=404)
    port = scen.get(f"{variant}_port")
    if not port:
        return JSONResponse({"error": f"{variant} için port yok"}, status_code=404)

    proc = _processes.pop(port, None)
    if proc is not None and proc.poll() is None:
        proc.terminate()
        return {"status": "stopped", "port": port, "via": "process"}

    # Panel kaydında yok (ör. panel yeniden başlatıldı) → porttan bulup öldür.
    if _lsof_kill(port):
        return {"status": "stopped", "port": port, "via": "lsof"}
    return {"status": "not_running", "port": port}


@app.post("/api/stop-all")
def api_stop_all():
    """Oturum sonu temizliği: bilinen tüm portlarda çalışan süreçleri öldürür."""
    stopped = []
    for port in _known_ports():
        proc = _processes.pop(port, None)
        if proc is not None and proc.poll() is None:
            proc.terminate()
            stopped.append(port)
        elif _lsof_kill(port):
            stopped.append(port)
    return {"status": "done", "stopped": stopped}


# --- Reverse proxy: interactive-lab arayüzünün senaryo backend'lerine erişimi ---------
# İstekleri (method, body, Cookie) hedef backend'e iletir; cevabı (status, body,
# Set-Cookie) tarayıcıya döndürür. Backend ayakta değilse otomatik başlatıp bekler.

# Backend'e iletirken/geri dönerken düşürülecek hop-by-hop / yeniden hesaplanan header'lar.
_HOP_HEADERS = {"host", "content-length", "connection", "keep-alive", "transfer-encoding"}
_RESP_SKIP = {"content-length", "transfer-encoding", "connection", "keep-alive", "server", "date"}


def _rewrite_cookie_path(set_cookie: str, prefix: str) -> str:
    """Set-Cookie'nin Path'ini bu variant'ın proxy prefix'ine sabitler.

    vulnerable ve fixed aynı 9000 origin'inden servis edildiği için, ikisi de 'session'
    adında cookie set ederse tarayıcıda çakışır. Path'i variant-özel prefix'e çekerek her
    cookie yalnızca kendi variant'ının isteklerinde gönderilir — çakışma önlenir."""
    parts = [p for p in set_cookie.split(";") if not p.strip().lower().startswith("path=")]
    parts.append(f" Path={prefix}")
    return ";".join(parts)


async def _ensure_running(scen: dict, variant: str) -> tuple[int | None, tuple[str, int] | None]:
    """Backend ayakta değilse başlatır ve dinlemeye başlamasını (kısa süre) bekler."""
    port = scen.get(f"{variant}_port")
    if not port:
        return None, (f"{variant} için port yok", 404)
    if _is_listening(port):
        return port, None
    _, err = _launch_backend(scen, variant)
    if err:
        return None, err
    for _ in range(50):  # ~10 sn (fail-secure backend'ler için de yeterli)
        if _is_listening(port):
            return port, None
        await asyncio.sleep(0.2)
    return None, (f"Backend {port} portunda ayağa kalkmadı", 502)


@app.api_route(
    "/api/proxy/{variant}/{modul}/{senaryo}/{path:path}",
    methods=["GET", "POST", "DELETE"],
)
async def api_proxy(variant: str, modul: str, senaryo: str, path: str, request: Request):
    if variant not in VARIANTS:
        return JSONResponse({"error": f"Geçersiz variant: {variant}"}, status_code=400)
    scen = _find_scenario(modul, senaryo)
    if scen is None:
        return JSONResponse({"error": "Senaryo bulunamadı"}, status_code=404)

    port, err = await _ensure_running(scen, variant)
    if err:
        return JSONResponse({"error": err[0]}, status_code=err[1])

    prefix = f"/api/proxy/{variant}/{modul}/{senaryo}"
    url = f"http://127.0.0.1:{port}/{path}"
    body = await request.body()
    fwd_headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP_HEADERS}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            upstream = await client.request(
                request.method,
                url,
                content=body,
                headers=fwd_headers,
                params=request.query_params,
                follow_redirects=False,
            )
    except httpx.RequestError as exc:
        return JSONResponse({"error": f"Backend'e ulaşılamadı: {exc}"}, status_code=502)

    # Cevabı yeniden inşa et: Set-Cookie'leri ayrı topla (path rewrite), gerisini geçir.
    set_cookies: list[str] = []
    passthrough: dict[str, str] = {}
    for key, value in upstream.headers.multi_items():
        lk = key.lower()
        if lk == "set-cookie":
            set_cookies.append(value)
        elif lk not in _RESP_SKIP:
            passthrough[key] = value

    response = Response(
        content=upstream.content, status_code=upstream.status_code, headers=passthrough
    )
    for sc in set_cookies:
        response.headers.append("set-cookie", _rewrite_cookie_path(sc, prefix))
    return response


# --- React (Vite) interactive-lab build'i: /app altında servis edilir -----------------
# dist/ henüz üretilmemişse (npm run build çalıştırılmadıysa) route'u sessizce atla.
_FRONTEND_DIST = BASE_DIR / "frontend" / "dist"
if _FRONTEND_DIST.is_dir():
    app.mount("/app", StaticFiles(directory=str(_FRONTEND_DIST), html=True), name="app")
