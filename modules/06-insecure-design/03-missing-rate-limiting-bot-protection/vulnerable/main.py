# CWE-770 (Allocation of Resources Without Limits or Throttling) +
# CWE-799 (Improper Control of Interaction Frequency): endpoint, otomatik/toplu
# kullanıma karşı HİÇBİR tasarım kontrolü içermez.
"""
Modül 06 — Insecure Design
Senaryo 3: Missing Rate Limiting / Bot Protection (VULNERABLE)

Bağlam (OWASP'ın scalper/bot örneği): Sınırlı stoklu bir ürün (ekran kartı, 100 adet)
satışa çıkar. Endpoint tek tek insan alıcılar için tasarlanmıştır.

Zafiyet: Ne istek frekansı ne de kişi başına satın alma sınırı vardır. Tek bir istemci
saniyeler içinde yüzlerce istek atıp tüm stoğu tüketebilir; gerçek müşteriler ürüne
hiç ulaşamaz. Saldırgan yine hiçbir kuralı ihlal etmez — sadece "satın al" işlemini
insan hızının çok üstünde tekrarlar.

Kusurun TASARIMSAL doğası: "Bu endpoint otomatik/toplu kullanılırsa ne olur?" sorusu
tasarım aşamasında hiç sorulmamıştır. Kimlik doğrulama, girdi doğrulama ve iş mantığı
tek başına doğrudur — eksik olan, ETKİLEŞİM FREKANSI üzerine bir tasarım kontrolüdür.

Çalıştırma: uvicorn main:app --port 8180
"""
# PORT: 8180
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

app = FastAPI()

INITIAL_STOCK = 100

PRODUCTS = {
    "gpu-5090": {"name": "Ekran Kartı RTX-5090", "price_tl": 89999, "stock": INITIAL_STOCK},
}

PURCHASE_LOG: list[dict] = []


class PurchaseRequest(BaseModel):
    product_id: str
    quantity: int = 1


@app.get("/status")
def status():
    return {"status": "up", "scenario": "missing-rate-limiting-bot-protection"}


@app.get("/stock")
def stock():
    return {
        "products": PRODUCTS,
        "total_purchases": len(PURCHASE_LOG),
        "per_client": _per_client_counts(),
    }


def _per_client_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for p in PURCHASE_LOG:
        counts[p["client"]] = counts.get(p["client"], 0) + p["quantity"]
    return counts


@app.post("/purchase")
def purchase(req: PurchaseRequest, request: Request):
    # ZAFIYET (tasarım): rate limit YOK, kişi başı limit YOK, bot tespiti YOK.
    # Aynı istemci arka arkaya sınırsız istek atabilir; her biri başarılı olur.
    product = PRODUCTS.get(req.product_id)
    if not product:
        raise HTTPException(status_code=404, detail="Ürün bulunamadı")

    if product["stock"] < req.quantity:
        raise HTTPException(status_code=409, detail="Stok tükendi")

    product["stock"] -= req.quantity
    client = request.client.host if request.client else "unknown"
    PURCHASE_LOG.append({"client": client, "product_id": req.product_id, "quantity": req.quantity})

    return {
        "purchased": True,
        "product_id": req.product_id,
        "quantity": req.quantity,
        "remaining_stock": product["stock"],
        "your_total_units": _per_client_counts().get(client, 0),
        "message": "Satın alma başarılı (hiçbir hız/adet sınırı uygulanmadı).",
    }


@app.post("/reset")
def reset():
    # Lab kolaylığı: stoğu tekrar doldurur. Gerçek sistemde bulunmaz.
    PRODUCTS["gpu-5090"]["stock"] = INITIAL_STOCK
    PURCHASE_LOG.clear()
    return {"reset": True, "stock": INITIAL_STOCK}
