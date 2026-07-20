# DEFANGED SIMULATION — no real malicious behavior, for educational demonstration only
"""
Modül 03 — Software Supply Chain Failures
Senaryo 4: Component RCE / Struts tarzı (FIXED)

Remediation: Uygulama kodu aynı — düzeltme, `data_parser` bileşeninin ifade
değerlendirmesini kaldıran GÜVENLİ SÜRÜME yükseltilmesidir (supply chain remediation:
sürüm pinleme + trusted/imzalı kaynak). Aynı `%{...}` girdisi artık zararsız, düz veri
olarak işlenir.

Çalıştırma: uvicorn main:app --port 8081
"""
# PORT: 8081
from fastapi import FastAPI
from pydantic import BaseModel

import data_parser

app = FastAPI()


class ParseRequest(BaseModel):
    payload: str


@app.get("/status")
def status():
    return {"status": "up", "parser": "data_parser", "parser_version": data_parser.__version__}


@app.post("/parse")
def parse(req: ParseRequest):
    # Aynı çağrı; güvenli sürüm girdiyi düz veri olarak işler, ifade değerlendirmez.
    result = data_parser.parse(req.payload)
    return result
