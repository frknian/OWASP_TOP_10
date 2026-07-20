# CWE-770 / CWE-799 — FIX.
# Dikkat: Bu fix tek satırlık bir kontrol değil; ürüne "adil dağıtım" tasarımı eklenir.
# İki bağımsız tasarım kontrolü birlikte çalışır: (1) etkileşim frekansı sınırı,
# (2) kişi başına toplam tahsis sınırı. Biri diğerinin yerine geçemez.
"""
Modül 06 — Insecure Design
Senaryo 3: Missing Rate Limiting / Bot Protection (FIXED)

Eklenen tasarım kontrolleri:
    (1) RATE LIMIT: İstemci başına 60 saniyelik kayan pencerede en fazla 5 istek.
        Aşılırsa 429 Too Many Requests + Retry-After. Bu, bot HIZINI kırar.
    (2) KİŞİ BAŞI TAHSİS LİMİTİ: İstemci başına en fazla 2 adet. Aşılırsa 403.
        Bu, bot yavaşlatılsa bile stoğun tek elde toplanmasını engeller.

Neden ikisi birden: Yalnızca rate limit olsaydı, saldırgan yavaşlayıp yine tüm stoğu
alırdı. Yalnızca adet limiti olsaydı, endpoint hâlâ istek seliyle boğulabilirdi.
Kontroller farklı tehditleri (frekans / adil dağıtım) karşılar.

Dış bağımlılık yok: rate limit, zaman damgası listeleriyle in-memory uygulanır.
Lab kolaylığı: İstemci kimliği IP'dir; farklı istemcileri simüle etmek için
opsiyonel `X-Client-Id` header'ı da desteklenir.

Çalıştırma: uvicorn main:app --port 8181
"""
# PORT: 8181
import time

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

app = FastAPI()

INITIAL_STOCK = 100
RATE_LIMIT_MAX_REQUESTS = 5  # pencere başına istek
RATE_LIMIT_WINDOW_SECONDS = 60  # kayan pencere
MAX_UNITS_PER_CLIENT = 2  # kişi başı toplam adet

PRODUCTS = {
    "gpu-5090": {"name": "Ekran Kartı RTX-5090", "price_tl": 89999, "stock": INITIAL_STOCK},
}

PURCHASE_LOG: list[dict] = []
REQUEST_TIMES: dict[str, list[float]] = {}  # client -> istek zaman damgaları


class PurchaseRequest(BaseModel):
    product_id: str
    quantity: int = 1


def _client_id(request: Request) -> str:
    # Gerçek sistemde: kimlik doğrulanmış kullanıcı + cihaz/IP birleşimi.
    header_id = request.headers.get("X-Client-Id")
    if header_id:
        return header_id
    return request.client.host if request.client else "unknown"


def _check_rate_limit(client: str) -> None:
    """(1) Kayan pencere rate limit — dış bağımlılık olmadan, zaman damgası bazlı."""
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW_SECONDS
    times = [t for t in REQUEST_TIMES.get(client, []) if t > window_start]  # eskileri at
    if len(times) >= RATE_LIMIT_MAX_REQUESTS:
        retry_after = int(RATE_LIMIT_WINDOW_SECONDS - (now - times[0])) + 1
        REQUEST_TIMES[client] = times
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Çok fazla istek",
                "limit": f"{RATE_LIMIT_MAX_REQUESTS} istek / {RATE_LIMIT_WINDOW_SECONDS} sn",
                "retry_after_seconds": retry_after,
            },
            headers={"Retry-After": str(retry_after)},
        )
    times.append(now)
    REQUEST_TIMES[client] = times


def _units_bought(client: str) -> int:
    return sum(p["quantity"] for p in PURCHASE_LOG if p["client"] == client)


@app.get("/status")
def status():
    return {"status": "up", "scenario": "missing-rate-limiting-bot-protection (fixed)"}


@app.get("/stock")
def stock():
    counts: dict[str, int] = {}
    for p in PURCHASE_LOG:
        counts[p["client"]] = counts.get(p["client"], 0) + p["quantity"]
    return {
        "products": PRODUCTS,
        "total_purchases": len(PURCHASE_LOG),
        "per_client": counts,
        "limits": {
            "rate_limit": f"{RATE_LIMIT_MAX_REQUESTS} istek / {RATE_LIMIT_WINDOW_SECONDS} sn",
            "max_units_per_client": MAX_UNITS_PER_CLIENT,
        },
    }


@app.post("/purchase")
def purchase(req: PurchaseRequest, request: Request):
    client = _client_id(request)

    # (1) Frekans kontrolü — stok mantığına GİRMEDEN önce uygulanır.
    _check_rate_limit(client)

    product = PRODUCTS.get(req.product_id)
    if not product:
        raise HTTPException(status_code=404, detail="Ürün bulunamadı")
    if req.quantity < 1:
        raise HTTPException(status_code=400, detail="quantity en az 1 olmalı")

    # (2) Adil dağıtım kontrolü — kişi başı toplam tahsis sınırı.
    already = _units_bought(client)
    if already + req.quantity > MAX_UNITS_PER_CLIENT:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Kişi başı satın alma limiti aşıldı",
                "your_total_units": already,
                "requested": req.quantity,
                "max_units_per_client": MAX_UNITS_PER_CLIENT,
            },
        )

    if product["stock"] < req.quantity:
        raise HTTPException(status_code=409, detail="Stok tükendi")

    product["stock"] -= req.quantity
    PURCHASE_LOG.append({"client": client, "product_id": req.product_id, "quantity": req.quantity})

    return {
        "purchased": True,
        "product_id": req.product_id,
        "quantity": req.quantity,
        "remaining_stock": product["stock"],
        "your_total_units": _units_bought(client),
        "max_units_per_client": MAX_UNITS_PER_CLIENT,
        "message": "Satın alma başarılı (hız ve adet limitleri içinde).",
    }


@app.post("/reset")
def reset():
    # Lab kolaylığı: stoğu ve sayaçları sıfırlar. Gerçek sistemde bulunmaz.
    PRODUCTS["gpu-5090"]["stock"] = INITIAL_STOCK
    PURCHASE_LOG.clear()
    REQUEST_TIMES.clear()
    return {"reset": True, "stock": INITIAL_STOCK}
