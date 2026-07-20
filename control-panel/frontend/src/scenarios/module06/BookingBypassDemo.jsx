import { useState } from 'react'
import { proxy, MODULE06 } from '../../api.js'
import { HowItWorks } from '../../ui.jsx'

const SENARYO = '02-business-logic-bypass-booking'
const ATTACKER = 'attacker'

const STEPS = [
  '"15 kişiye kadar depozito isteme" iş kuralı yalnızca 15 ve ALTI için yazılmıştır.',
  'Kodda "if seats <= 15" dalının bir else\'i YOKTUR — 15 üstü hiç tasarlanmamıştır (asıl tasarım boşluğu).',
  'seats=600 isteği geçerli JSON, geçerli tip: saldırgan kuralı İHLAL etmiyor, hiç düşünülmemiş ölçekte kullanıyor.',
  'Kümülatif takip de yok → 15\'er 15\'er birçok istekle salon doldurulur; her istek tek başına "kurala uygun".',
  'Fix TASARIM değişikliğidir: eşik üstü artık tanımlı (depozito zorunlu, 402), kullanıcı başına kümülatif limit (409) ve kapasite tavanı eklendi.',
]

const VULN_CODE = `@app.post("/book")
def book(req: BookRequest):
    deposit_required = False
    if req.seats <= FREE_GROUP_LIMIT:   # 15
        deposit_required = False
    # (else dalı YOK — asıl tasarım boşluğu burası)
    entry["seats"] += req.seats          # kümülatif kontrol yok
                                         # kapasite kontrolü de yok
    return {"confirmed": True, "deposit_required": deposit_required, ...}`

const FIXED_CODE = `@app.post("/book")
def book(req: BookRequest):              # username ZORUNLU
    if req.seats > MAX_SEATS_PER_REQUEST:               # 100
        raise HTTPException(400, "Tek istekte en fazla 100 koltuk...")
    if entry["seats"] + req.seats > MAX_OPEN_SEATS_PER_USER:   # 30 kümülatif
        raise HTTPException(409, "Kümülatif rezervasyon limiti aşıldı")
    if total_all + req.seats > HALL_CAPACITY:           # 500 tavan
        raise HTTPException(409, "Salon kapasitesi yetersiz")
    if req.seats > FREE_GROUP_LIMIT:                    # 15 üstü ARTIK TANIMLI
        raise HTTPException(402, {"status": "PENDING_DEPOSIT", ...})`

function statusColor(s) {
  if (s >= 200 && s < 300) return '#7CFFB2'
  if (s >= 400) return '#ff9aa0'
  return '#d3d9e6'
}

function BookPanel({ title, result }) {
  if (!result) {
    return (
      <div className="panel">
        <h3>{title}</h3>
        <div className="muted">Henüz istek atılmadı.</div>
      </div>
    )
  }
  const d = result.data || {}
  const confirmedFree = result.ok && d.deposit_required === false
  const cls = confirmedFree ? 'panel allowed' : 'panel blocked'
  return (
    <div className={cls}>
      <h3>
        {title} <span className="badge" style={{ color: statusColor(result.status) }}>HTTP {result.status}</span>
      </h3>
      {result.ok && typeof d === 'object' && (
        <div className="statusline">
          {d.seats_this_request != null && <>koltuk: <b>{d.seats_this_request}</b> · </>}
          {d.deposit_required != null && <>depozito: <b>{d.deposit_required ? 'GEREKLİ' : 'YOK'}</b> · </>}
          {d.value_locked_tl != null && <>değer: <b>{d.value_locked_tl.toLocaleString('tr-TR')} TL</b> · </>}
          {d.overbooked != null && <>overbooked: <b style={{ color: d.overbooked ? '#ff9aa0' : '#7CFFB2' }}>{String(d.overbooked)}</b></>}
        </div>
      )}
      <pre>{typeof d === 'string' ? d : JSON.stringify(d, null, 2)}</pre>
    </div>
  )
}

export default function BookingBypassDemo() {
  const [seats, setSeats] = useState(15)
  const [results, setResults] = useState({})
  const [cumulative, setCumulative] = useState(null) // {vuln:[], fixed:[]}
  const [busy, setBusy] = useState(false)

  async function resetBoth() {
    await proxy('vulnerable', MODULE06, SENARYO, 'reset', { method: 'POST' })
    await proxy('fixed', MODULE06, SENARYO, 'reset', { method: 'POST' })
  }

  async function book() {
    setBusy(true)
    setCumulative(null)
    await resetBoth()
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      next[v] = await proxy(v, MODULE06, SENARYO, 'book', {
        method: 'POST',
        body: { username: ATTACKER, seats: Number(seats) },
      })
    }
    setResults(next)
    setBusy(false)
  }

  async function cumulativeAttack() {
    setBusy(true)
    setResults({})
    await resetBoth()
    const acc = { vulnerable: [], fixed: [] }
    for (const v of ['vulnerable', 'fixed']) {
      for (let i = 1; i <= 5; i++) {
        const r = await proxy(v, MODULE06, SENARYO, 'book', {
          method: 'POST',
          body: { username: ATTACKER, seats: 15 },
        })
        const total = r.data?.user_total_seats ?? (r.data?.detail?.user_total_seats)
        acc[v].push({ i, status: r.status, ok: r.ok, total })
        setCumulative({ ...acc, vulnerable: [...acc.vulnerable], fixed: [...acc.fixed] })
      }
    }
    setBusy(false)
  }

  const v = results.vulnerable
  const f = results.fixed

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 2 — Business Logic Bypass (Grup Rezervasyonu)</h2>
        <div className="meta">CVSS 8.2 (High) · CWE-841 / CWE-770 · A06:2025</div>
        <p>
          Sinema "15 kişiye kadar depozitosuz" kuralını koyar; ama <b>15'in üstü hiç tasarlanmamıştır</b>.
          Saldırgan tek istekte 600 koltuğu depozitosuz rezerve edebilir (overbooking). Fix, iş kuralının
          kendisini yeniden tasarlar. Saldırgan kurallara <i>uygun</i> davrandığı için WAF/girdi doğrulama
          bunu yakalayamaz.
        </p>
      </header>

      <div className="actionbar">
        <div className="field">
          <label>Koltuk sayısı</label>
          <input type="number" value={seats} onChange={(e) => setSeats(e.target.value)} style={{ width: 110 }} />
        </div>
        <button className="btn" onClick={() => setSeats(600)} disabled={busy}>
          600 Koltuk Doldur
        </button>
        <button className="btn primary" onClick={book} disabled={busy}>
          Rezervasyon Yap (iki sürüme)
        </button>
        <button className="btn" onClick={cumulativeAttack} disabled={busy}>
          5×15 Koltuk Gönder (kümülatif saldırı)
        </button>
      </div>

      {v && (
        v.ok && v.data?.deposit_required === false ? (
          <div className="banner leak">
            🔓 Overbooking — depozito atlatıldı: {v.data.seats_this_request} koltuk, {(v.data.value_locked_tl ?? 0).toLocaleString('tr-TR')} TL değer, sıfır depozito
            {v.data.overbooked ? ` (kapasite ${v.data.hall_capacity} aşıldı)` : ''}.
          </div>
        ) : (
          <div className="banner neutral">Vulnerable: HTTP {v.status}</div>
        )
      )}
      {f && (
        f.status === 400 || f.status === 402 || f.status === 409 ? (
          <div className="banner safe">
            🔒 Tasarım kuralı: eşik üstü artık tanımlı — HTTP {f.status}
            {f.status === 400 ? ' (tek istek tavanı)' : f.status === 402 ? ' (depozito gerekli)' : ' (kümülatif/kapasite limiti)'}.
          </div>
        ) : f.ok ? (
          <div className="banner neutral">Fixed: HTTP {f.status} (limit içinde, meşru rezervasyon)</div>
        ) : (
          <div className="banner neutral">Fixed: HTTP {f.status}</div>
        )
      )}

      {(v || f) && (
        <div className="compare">
          <BookPanel title="Vulnerable" result={v} />
          <BookPanel title="Fixed" result={f} />
        </div>
      )}

      {/* Kümülatif saldırı tablosu */}
      {cumulative && (
        <div className="compare" style={{ marginTop: 12 }}>
          {['vulnerable', 'fixed'].map((variant) => (
            <div className={variant === 'vulnerable' ? 'panel allowed' : 'panel blocked'} key={variant}>
              <h3>{variant === 'vulnerable' ? 'Vulnerable' : 'Fixed'} — 5×15 koltuk (kümülatif)</h3>
              <ol className="steps">
                {cumulative[variant].map((s) => (
                  <li key={s.i}>
                    istek {s.i} →{' '}
                    <b style={{ color: statusColor(s.status) }}>{s.status} {s.ok ? '✅' : '⛔'}</b>
                    {s.total != null && <> · toplam: <b>{s.total}</b> koltuk</>}
                  </li>
                ))}
              </ol>
              {variant === 'vulnerable' ? (
                <div className="banner leak">🔓 Her istek 15'i aşmadı, hepsi "kurala uygun" — toplam sınırsız büyüyor.</div>
              ) : (
                <div className="banner safe">🔒 30 koltuk kümülatif tavanı aşılınca istek 409 ile durdu.</div>
              )}
            </div>
          ))}
        </div>
      )}

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
