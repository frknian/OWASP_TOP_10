# CWE-841 (Improper Enforcement of Behavioral Workflow) + CWE-770 (Allocation of
# Resources Without Limits or Throttling): iş kuralı yalnızca "beklenen" kullanım
# (happy path) için tasarlanmış; kuralın dışına çıkan kullanım için HİÇBİR tanım yok.
"""
Modül 06 — Insecure Design
Senaryo 2: Business Logic Bypass / Grup Rezervasyonu (VULNERABLE)

Bağlam (OWASP'ın sinema örneği): Sinema, grup rezervasyonlarını teşvik etmek için
"15 kişiye kadar depozito istemeyelim" iş kuralını koyar.

Zafiyet: Kural koda "15 ve altı depozitosuz" olarak yazılmıştır — ama 15'in ÜSTÜ için
hiçbir kural TASARLANMAMIŞTIR. Sonuç:
    * Tek istekte seats=600 gönderilebilir → depozitosuz onaylanır.
    * Kümülatif takip yoktur → arka arkaya 15'lik istekler binlerce koltuğa ulaşır.
    * Salon kapasitesi (500) hiç kontrol edilmez → overbooking mümkündür.

Kusurun TASARIMSAL doğası: Saldırgan hiçbir kuralı İHLAL etmiyor — uygulamayı tam da
sunulduğu gibi, ama kimsenin düşünmediği ölçekte kullanıyor. Girdi doğrulaması,
WAF veya "injection" filtreleri bunu yakalayamaz: istek her açıdan geçerlidir.

Çalıştırma: uvicorn main:app --port 8170
"""
# PORT: 8170
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

HALL_CAPACITY = 500  # salonun fiziksel koltuk sayısı (vulnerable sürümde HİÇ kontrol edilmez)
FREE_GROUP_LIMIT = 15  # "15 kişiye kadar depozitosuz" iş kuralı
SEAT_PRICE = 120  # TL

# username -> {"seats": toplam, "bookings": [...]}
BOOKINGS: dict[str, dict] = {}


class BookRequest(BaseModel):
    seats: int
    username: str = "guest"  # kimlik opsiyonel — kümülatif takip zaten yapılmıyor


@app.get("/status")
def status():
    return {"status": "up", "scenario": "business-logic-bypass-booking"}


@app.get("/bookings")
def list_bookings():
    total = sum(b["seats"] for b in BOOKINGS.values())
    return {
        "hall_capacity": HALL_CAPACITY,
        "total_seats_booked": total,
        "overbooked": total > HALL_CAPACITY,
        "per_user": {u: b["seats"] for u, b in BOOKINGS.items()},
    }


@app.post("/book")
def book(req: BookRequest):
    # ZAFIYET (tasarım): Kural yalnızca "15 ve altı depozitosuz" için yazılmış.
    # 15'in ÜSTÜ için bir "else" YOK — çünkü tasarım aşamasında kimse "ya 600 isterse?"
    # sorusunu sormamış. deposit_required bu yüzden her durumda False kalıyor.
    deposit_required = False
    if req.seats <= FREE_GROUP_LIMIT:
        deposit_required = False
    # (else dalı bilinçli olarak YOK — asıl tasarım boşluğu burası)

    # ZAFIYET: Kümülatif kontrol yok — kullanıcının toplam açık rezervasyonuna bakılmıyor.
    # ZAFIYET: Salon kapasitesi kontrol edilmiyor → overbooking serbest.
    entry = BOOKINGS.setdefault(req.username, {"seats": 0, "bookings": []})
    entry["seats"] += req.seats
    entry["bookings"].append(req.seats)

    total_all = sum(b["seats"] for b in BOOKINGS.values())
    return {
        "confirmed": True,
        "username": req.username,
        "seats_this_request": req.seats,
        "deposit_required": deposit_required,
        "deposit_amount": 0,
        "user_total_seats": entry["seats"],
        "total_seats_booked": total_all,
        "hall_capacity": HALL_CAPACITY,
        "overbooked": total_all > HALL_CAPACITY,
        "value_locked_tl": req.seats * SEAT_PRICE,
        "message": f"{req.seats} koltuk depozitosuz rezerve edildi.",
    }


@app.post("/reset")
def reset():
    # Lab kolaylığı: tekrar tekrar test edebilmek için. Gerçek sistemde bulunmaz.
    BOOKINGS.clear()
    return {"reset": True}
