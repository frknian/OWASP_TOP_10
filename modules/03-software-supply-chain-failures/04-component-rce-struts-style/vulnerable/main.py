# DEFANGED SIMULATION — no real malicious behavior, for educational demonstration only
"""
Modül 03 — Software Supply Chain Failures
Senaryo 4: Component RCE / Struts tarzı (VULNERABLE)

Zafiyet: Uygulama, gelen veriyi işlemek için zafiyetli `data_parser` bileşenine güvenir.
`POST /parse`, kullanıcı girdisini doğrudan bu ayrıştırıcıya verir. Ayrıştırıcı, girdideki
`%{...}` ifadelerini kod olarak değerlendirdiği için, saldırgan kontrollü veri sunucuda
yürütme yoluna girer (Struts OGNL injection deseni). Uygulama kodu masumdur; kusur
güvenilen bileşenin içindedir.

Çalıştırma: uvicorn main:app --port 8080
"""
# PORT: 8080
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
    # ZAFIYET: Girdi hiçbir doğrulama olmadan zafiyetli ayrıştırıcıya geçiyor.
    result = data_parser.parse(req.payload)
    return result
