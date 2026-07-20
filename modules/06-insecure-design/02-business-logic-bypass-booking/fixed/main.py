# CWE-841 / CWE-770 — FIX.
# Dikkat: Bu fix bir girdi doğrulama yaması DEĞİL. İş kuralının KENDİSİ yeniden
# tasarlandı: "15 kişiye kadar depozitosuz" kuralının eksik kalan tarafı (15 ÜSTÜ ne
# olacak?) tanımlandı ve kaynak tahsisine sınırlar konuldu.
"""
Modül 06 — Insecure Design
Senaryo 2: Business Logic Bypass / Grup Rezervasyonu (FIXED)

Yeniden tasarlanan iş kuralı — üç katmanlı:
    (a) TEK İSTEK EŞİĞİ: seats > 15 ise depozito ZORUNLU. Rezervasyon otomatik
        onaylanmaz; PENDING_DEPOSIT durumuna düşer ve 402 ile depozitoya yönlendirilir.
    (b) KÜMÜLATİF LİMİT: Kullanıcı başına toplam açık rezervasyon 30 koltukla sınırlı.
        Böylece "15'er 15'er 100 istek" yoluyla eşiği aşındırma kapatılır.
    (c) KAPASİTE TAVANI: Toplam rezervasyon salon kapasitesini (500) aşamaz →
        overbooking yapısal olarak imkânsız.

Ek olarak makul bir mutlak üst sınır (tek istekte en fazla 100) konuldu: bu, saçma
değerlerin iş akışına hiç girmemesini sağlar.

Kimlik artık ZORUNLU (username): kümülatif kural ancak bir özneye bağlanabilirse
uygulanabilir. Bu da bir tasarım kararıdır — anonim toplu rezervasyon kaldırıldı.

Çalıştırma: uvicorn main:app --port 8171
"""
# PORT: 8171
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

HALL_CAPACITY = 500
FREE_GROUP_LIMIT = 15  # bu sayıya kadar depozitosuz
MAX_SEATS_PER_REQUEST = 100  # mutlak üst sınır
MAX_OPEN_SEATS_PER_USER = 30  # kümülatif limit
SEAT_PRICE = 120  # TL
DEPOSIT_RATE = 0.25  # depozito = koltuk bedelinin %25'i

BOOKINGS: dict[str, dict] = {}
PENDING: dict[str, dict] = {}  # depozito bekleyen rezervasyonlar


class BookRequest(BaseModel):
    seats: int
    username: str  # ZORUNLU: kümülatif kural bir özne olmadan uygulanamaz


@app.get("/status")
def status():
    return {"status": "up", "scenario": "business-logic-bypass-booking (fixed)"}


@app.get("/bookings")
def list_bookings():
    total = sum(b["seats"] for b in BOOKINGS.values())
    return {
        "hall_capacity": HALL_CAPACITY,
        "total_seats_booked": total,
        "remaining_capacity": HALL_CAPACITY - total,
        "overbooked": total > HALL_CAPACITY,  # tasarım gereği asla True olamaz
        "per_user": {u: b["seats"] for u, b in BOOKINGS.items()},
        "pending_deposit": {u: p["seats"] for u, p in PENDING.items()},
    }


@app.post("/book")
def book(req: BookRequest):
    if req.seats < 1:
        raise HTTPException(status_code=400, detail="seats en az 1 olmalı")

    # (0) Mutlak üst sınır — saçma değerler iş akışına hiç girmez.
    if req.seats > MAX_SEATS_PER_REQUEST:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Tek istekte en fazla {MAX_SEATS_PER_REQUEST} koltuk rezerve edilebilir. "
                f"Daha büyük gruplar için kurumsal satış sürecine yönlendirilirsiniz."
            ),
        )

    entry = BOOKINGS.setdefault(req.username, {"seats": 0, "bookings": []})

    # (b) KÜMÜLATİF LİMİT — arka arkaya küçük isteklerle eşiği aşındırma kapatıldı.
    if entry["seats"] + req.seats > MAX_OPEN_SEATS_PER_USER:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "Kümülatif rezervasyon limiti aşıldı",
                "user_total_seats": entry["seats"],
                "requested": req.seats,
                "max_open_seats_per_user": MAX_OPEN_SEATS_PER_USER,
            },
        )

    # (c) KAPASİTE TAVANI — overbooking yapısal olarak engellenir.
    total_all = sum(b["seats"] for b in BOOKINGS.values())
    if total_all + req.seats > HALL_CAPACITY:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "Salon kapasitesi yetersiz",
                "total_seats_booked": total_all,
                "hall_capacity": HALL_CAPACITY,
                "requested": req.seats,
            },
        )

    # (a) TEK İSTEK EŞİĞİ — 15 üstü artık TANIMLI: depozito zorunlu, otomatik onay yok.
    if req.seats > FREE_GROUP_LIMIT:
        deposit = round(req.seats * SEAT_PRICE * DEPOSIT_RATE, 2)
        PENDING[req.username] = {"seats": req.seats, "deposit": deposit}
        raise HTTPException(
            status_code=402,  # Payment Required
            detail={
                "error": "Depozito gerekli",
                "status": "PENDING_DEPOSIT",
                "seats": req.seats,
                "free_group_limit": FREE_GROUP_LIMIT,
                "deposit_amount_tl": deposit,
                "message": (
                    f"{FREE_GROUP_LIMIT} kişiden büyük gruplar depozitosuz onaylanmaz. "
                    f"Rezervasyon {deposit} TL depozito ödenene kadar PENDING_DEPOSIT durumundadır."
                ),
            },
        )

    # Buraya yalnızca kuralın tasarlandığı happy path ulaşır: 1..15 koltuk, depozitosuz.
    entry["seats"] += req.seats
    entry["bookings"].append(req.seats)
    return {
        "confirmed": True,
        "username": req.username,
        "seats_this_request": req.seats,
        "deposit_required": False,
        "user_total_seats": entry["seats"],
        "max_open_seats_per_user": MAX_OPEN_SEATS_PER_USER,
        "total_seats_booked": total_all + req.seats,
        "hall_capacity": HALL_CAPACITY,
        "message": f"{req.seats} koltuk depozitosuz rezerve edildi (limit içinde).",
    }


@app.post("/reset")
def reset():
    # Lab kolaylığı: tekrar tekrar test edebilmek için. Gerçek sistemde bulunmaz.
    BOOKINGS.clear()
    PENDING.clear()
    return {"reset": True}
