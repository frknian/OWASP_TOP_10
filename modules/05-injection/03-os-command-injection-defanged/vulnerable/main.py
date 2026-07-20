# DEFANGED SIMULATION — no real shell execution, for educational demonstration only
# CWE-78 (OS Command Injection): kullanıcı girdisi bir komut string'ine gömülür.
"""
Modül 05 — Injection
Senaryo 3: OS Command Injection (VULNERABLE, DEFANGED)

Zafiyet: `POST /diagnose`, gelen `domain` değerini bir kabuk komutuna string olarak
gömer (f"nslookup {domain}"). Girdi kabuk tarafından yorumlanacağından, `;` `|` `&&`
gibi metakarakterlerle saldırgan ek komut çalıştırabilir (örn. "example.com; cat /etc/passwd").

DEFANGED: Komut GERÇEKTE çalıştırılmaz (os.system/subprocess YOK). Bunun yerine oluşan
TAM komut string'i döndürülür — böylece enjeksiyonun kabuğa nasıl bir komut ürettiği
güvenle görülür.

Çalıştırma: uvicorn main:app --port 8140
"""
# PORT: 8140
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class DiagnoseRequest(BaseModel):
    domain: str


@app.get("/status")
def status():
    return {"status": "up", "scenario": "os-command-injection-defanged"}


@app.post("/diagnose")
def diagnose(req: DiagnoseRequest):
    # ZAFIYET: domain kullanıcı girdisi olduğu halde komut string'ine gömülüyor.
    # Gerçek bir sistemde bu string subprocess'e shell=True ile verilseydi, `;` sonrası
    # ikinci komut da çalışırdı. Burada DEFANGED — sadece oluşan komutu gösteriyoruz.
    command = f"nslookup {req.domain}"
    return {
        "simulation": f"[SİMÜLASYON] Bu komut çalıştırılırdı: {command}",
        "built_command": command,
        "note": "Gerçek ortamda ';' ve benzeri metakarakterlerle enjekte edilen komut da çalışırdı.",
    }
