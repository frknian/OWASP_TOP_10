# DEFANGED SIMULATION — no real malicious behavior, for educational demonstration only
"""
Modül 03 — Software Supply Chain Failures
Senaryo 1: Vulnerable Component / Log4Shell tarzı (VULNERABLE)

Zafiyet: Uygulama, log almak için zafiyetli bir üçüncü taraf kütüphaneye
(`vulnerable_logger`) bağımlıdır. `POST /log` endpoint'i, kullanıcının gönderdiği
mesajı doğrudan bu kütüphaneye geçirir. Kütüphane mesaj içindeki `${...}` ifadelerini
"değerlendirdiği" için, kullanıcı kontrollü girdi (Log4Shell'de olduğu gibi) yürütme
yoluna girer.

Dikkat: Uygulama KODUNDA bariz bir hata yok — sadece "gelen mesajı logla" diyor.
Kusur, GÜVENİLEN BAĞIMLILIĞIN içindedir. A03:2025'in özü budur: sizin yazmadığınız
bir bileşenin zafiyeti sizin uygulamanızı da zafiyetli yapar.

Çalıştırma: uvicorn main:app --port 8050
"""
# PORT: 8050
from fastapi import FastAPI
from pydantic import BaseModel

import vulnerable_logger

app = FastAPI()


class LogEntry(BaseModel):
    message: str


@app.get("/status")
def status():
    return {"status": "up", "logger": "vulnerable_logger", "logger_version": vulnerable_logger.__version__}


@app.post("/log")
def write_log(entry: LogEntry):
    # ZAFIYET: Kullanıcı girdisi hiçbir arındırma olmadan zafiyetli logger'a geçiyor.
    # Uygulama "sadece logluyorum" sanıyor; ama logger mesajı yorumluyor.
    logged_line = vulnerable_logger.log(entry.message)
    return {"logged": logged_line}
