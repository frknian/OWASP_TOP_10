"""
Modül 02 — Security Misconfiguration
Senaryo 4: Public Cloud Storage Misconfiguration (VULNERABLE)

Zafiyet: Bir cloud storage "bucket"ının (burada lokal `bucket/` dizini ile simüle
ediliyor) yanlış varsayılan erişim izinleriyle herkese açık bırakılması. Dosya adını
bilen ya da tahmin eden HERKES, hiçbir kimlik doğrulama/yetkilendirme olmadan hassas
veriye (musteri_listesi.csv) erişebiliyor.

ÖNEMLİ: Bu senaryo GERÇEK bir cloud servisine (AWS S3, Azure Blob, GCP CS) istek
ATMAZ. Proje "sadece lokal lab" kuralına sadık kalır; aynı zafiyet sınıfı — yanlış
varsayılan erişim izinleri → herkese açık hassas veri — lokal bir mock storage
endpoint'i ile simüle edilir. Gerçek dünya karşılığı için report.md'ye bakınız.

Çalıştırma: uvicorn main:app --port 8040
"""
# PORT: 8040
import os

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

app = FastAPI()

BUCKET_DIR = os.path.join(os.path.dirname(__file__), "bucket")


@app.get("/")
def index():
    return {"app": "Acme Cloud Storage (mock)", "status": "running"}


@app.get("/storage/{filename}", response_class=PlainTextResponse)
def get_object(filename: str):
    # ZAFIYET: "Bucket"taki nesne, HİÇBİR authentication/authorization kontrolü olmadan
    # servis ediliyor. Bu, gerçek dünyada bir S3 bucket'ının "public-read" bırakılması
    # (Block Public Access kapalı) veya Azure Blob'un "Container/Blob" public access
    # seviyesine ayarlanmasıyla birebir aynı sonucu doğurur: nesnenin adını (anahtarını)
    # bilen anonim bir istemci veriyi doğrudan indirebilir.
    object_path = os.path.join(BUCKET_DIR, filename)
    with open(object_path, "r", encoding="utf-8") as f:
        return f.read()
