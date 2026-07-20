# DEFANGED SIMULATION — no real pickle deserialization executed, for educational
# demonstration only.
# CWE-502 (Deserialization of Untrusted Data): sunucu, client'tan gelen serileştirilmiş
# state'i hiçbir imza/doğrulama olmadan geri yükler. Gerçek bir sistemde bu pickle.loads()
# çağrısı olurdu; burada GERÇEKTE ÇALIŞTIRILMAZ — yalnızca tehlikeli payload tespit edilip
# "çalışsaydı ne olurdu" simüle edilir.
"""
Modül 08 — Software or Data Integrity Failures
Senaryo 1: Insecure Deserialization (VULNERABLE, DEFANGED)

Bağlam: Bir "kullanıcı tercihi" state'i (örn. {"theme": "dark"}) sunucu tarafından
serialize edilip client'a gönderilir; client bunu aynen geri POST eder ve sunucu
"geri yükler". Bu, state'i client'a emanet eden (trust boundary ihlali) yaygın bir
anti-pattern'dir.

Zafiyet: Gelen veri hiçbir imza/bütünlük kontrolünden geçmez. Gerçek bir pickle
tabanlı implementasyonda `pickle.loads(base64.b64decode(state))` çağrısı, saldırganın
`__reduce__` ile gömdüğü keyfi kodu deserialize sırasında ÇALIŞTIRIRDI (RCE).

DEFANGED: Bu labda gerçek pickle.loads YOK. Sunucu, base64 içeriğini decode edip
tehlikeli bir pattern (`__reduce__`, `os.system`, `subprocess`, `nt.system`...) arar;
bulursa "[SİMÜLASYON] Bu veri deserialize edilseydi şu kod çalışırdı: <payload>" döner.

Çalıştırma: uvicorn main:app --port 8220
"""
# PORT: 8220
import base64
import re

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

# Sunucunun tuttuğu varsayılan state (client'a "pickle-benzeri" base64 olarak gider).
DEFAULT_STATE = {"theme": "dark", "language": "tr", "sidebar": "expanded"}

# Gerçek pickle opcode'larını taklit eden, tehlikeli __reduce__ payload'ını içeren
# imza kalıpları (defanged tespit için).
DANGEROUS_PATTERNS = [
    r"__reduce__",
    r"os\.system",
    r"subprocess",
    r"nt\.system",
    r"posix\.system",
    r"builtins\.eval",
    r"builtins\.exec",
    r"cos\nsystem",  # gerçek pickle'da "c os\nsystem\n" GLOBAL opcode'unu taklit
]


class RestoreRequest(BaseModel):
    state: str  # base64 string (pickle-benzeri, defanged)


def _fake_pickle_encode(obj: dict) -> str:
    """
    Gerçek pickle KULLANMAZ. Yalnızca pickle'ın ürettiğine benzeyen, decode edilebilir
    bir base64 string üretir: "PICKLE;theme=dark;language=tr;..." formatı.
    Amaç, client'a "opak serileştirilmiş veri" görünümü vermek — defanged.
    """
    body = "PICKLE;" + ";".join(f"{k}={v}" for k, v in obj.items())
    return base64.b64encode(body.encode()).decode()


@app.get("/status")
def status():
    return {"status": "up", "scenario": "insecure-deserialization-defanged"}


@app.get("/get-state")
def get_state():
    # ZAFIYET: state client'a emanet ediliyor + hiçbir imza eklenmiyor.
    return {
        "state_encoded": _fake_pickle_encode(DEFAULT_STATE),
        "note": "Bu 'pickle-benzeri' base64 veriyi POST /restore-state ile geri gönderin.",
    }


@app.post("/restore-state")
def restore_state(req: RestoreRequest):
    # ZAFIYET: gelen veri imza/bütünlük kontrolünden GEÇMEZ. (DEFANGED — gerçek
    # pickle.loads çağrılmaz; tehlikeli payload yalnızca tespit edilip simüle edilir.)
    try:
        decoded = base64.b64decode(req.state).decode("utf-8", errors="replace")
    except Exception:
        decoded = "<decode edilemedi>"

    for pat in DANGEROUS_PATTERNS:
        m = re.search(pat, decoded)
        if m:
            return {
                "restored": False,
                "simulation": (
                    "[SİMÜLASYON] Bu veri deserialize edilseydi şu kod çalışırdı: "
                    f"{decoded}"
                ),
                "detected_pattern": m.group(0),
                "note": "Gerçek pickle.loads() çağrılmadı (DEFANGED). Gerçek sistemde RCE olurdu.",
            }

    # Tehlikeli pattern yok → "zararsız state" gibi davran ve geri yükle.
    return {
        "restored": True,
        "state_raw": decoded,
        "message": "Durum geri yüklendi.",
        "note": "Hiçbir imza/doğrulama yapılmadı — veri olduğu gibi kabul edildi.",
    }
