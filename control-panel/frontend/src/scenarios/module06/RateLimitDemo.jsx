import { useState } from 'react'
import { proxy, MODULE06 } from '../../api.js'
import { HowItWorks } from '../../ui.jsx'

const SENARYO = '03-missing-rate-limiting-bot-protection'
const N = 50
const PRODUCT = 'gpu-5090'

const STEPS = [
  'Satın alma endpoint\'i tek tek insan alıcılar varsayımıyla tasarlandı; frekans/adet sınırı hiç düşünülmedi.',
  'Vulnerable: rate limit YOK, kişi başı limit YOK → tek istemci saniyeler içinde tüm stoğu (100 adet) tüketir.',
  'Fix iki BAĞIMSIZ kontrol ekler: (1) rate limit (5 istek/60 sn) botun HIZINI kırar, (2) kişi başı 2 adet limiti stoğun tek elde toplanmasını engeller.',
  'İkisi de gerekli: yalnız rate limit olsa bot yavaşlayıp yine tüm stoğu alırdı; yalnız adet limiti olsa endpoint istek seliyle boğulurdu.',
  'Rate limit stok mantığından ÖNCE uygulanır → reddedilen istek iş mantığı/DB kaynağı tüketmez; 429 ile Retry-After döner.',
]

const VULN_CODE = `@app.post("/purchase")
def purchase(req: PurchaseRequest, request: Request):
    # rate limit YOK, kişi başı limit YOK, bot tespiti YOK
    product["stock"] -= req.quantity
    return {"purchased": True, "remaining_stock": product["stock"], ...}`

const FIXED_CODE = `def _check_rate_limit(client):          # (1) FREKANS: 5 istek / 60 sn (kayan pencere)
    times = [t for t in REQUEST_TIMES.get(client, []) if t > now - 60]
    if len(times) >= 5:
        raise HTTPException(429, {...}, headers={"Retry-After": str(retry_after)})

@app.post("/purchase")
def purchase(req, request):
    _check_rate_limit(client)           # stok mantığından ÖNCE
    if already + req.quantity > MAX_UNITS_PER_CLIENT:   # (2) ADİL DAĞITIM: kişi başı 2
        raise HTTPException(403, "Kişi başı satın alma limiti aşıldı")`

function controlLabel(status) {
  if (status === 200) return '—'
  if (status === 403) return 'kişi başı limit'
  if (status === 429) return 'rate limit'
  if (status === 409) return 'stok tükendi'
  return ''
}
function statusColor(s) {
  if (s === 200) return '#7CFFB2'
  return '#ff9aa0'
}

export default function RateLimitDemo() {
  const [busy, setBusy] = useState(false)
  const [vuln, setVuln] = useState(null) // {done, ok, rejected, stock}
  const [fixedRows, setFixedRows] = useState(null) // [{i,status}]
  const [fixedStock, setFixedStock] = useState(null)

  async function run() {
    setBusy(true)
    setVuln({ done: 0, ok: 0, rejected: 0, stock: null })
    setFixedRows(null)
    setFixedStock(null)

    // --- VULNERABLE: 50 istek, canlı sayaç ---
    await proxy('vulnerable', MODULE06, SENARYO, 'reset', { method: 'POST' })
    let ok = 0
    let rejected = 0
    for (let i = 1; i <= N; i++) {
      const r = await proxy('vulnerable', MODULE06, SENARYO, 'purchase', {
        method: 'POST',
        body: { product_id: PRODUCT, quantity: 1 },
      })
      if (r.ok) ok++
      else rejected++
      setVuln({ done: i, ok, rejected, stock: null })
    }
    const vStock = await proxy('vulnerable', MODULE06, SENARYO, 'stock')
    setVuln({ done: N, ok, rejected, stock: vStock.data?.products?.[PRODUCT]?.stock })

    // --- FIXED: aynı 50 istek, istek-istek tablo (aynı client) ---
    await proxy('fixed', MODULE06, SENARYO, 'reset', { method: 'POST' })
    const rows = []
    for (let i = 1; i <= N; i++) {
      const r = await proxy('fixed', MODULE06, SENARYO, 'purchase', {
        method: 'POST',
        body: { product_id: PRODUCT, quantity: 1 },
        headers: { 'X-Client-Id': 'bot-1' },
      })
      rows.push({ i, status: r.status })
      setFixedRows([...rows])
    }
    const fStock = await proxy('fixed', MODULE06, SENARYO, 'stock')
    setFixedStock(fStock.data?.products?.[PRODUCT]?.stock)

    setBusy(false)
  }

  const pct = vuln ? Math.round((vuln.done / N) * 100) : 0
  const fixedOk = fixedRows ? fixedRows.filter((r) => r.status === 200).length : 0
  const fixedRejected = fixedRows ? fixedRows.filter((r) => r.status !== 200).length : 0
  // Tabloyu sıkıştır: ilk 8 satır + kalanların özeti
  const shownRows = fixedRows ? fixedRows.slice(0, 8) : []
  const restRows = fixedRows ? fixedRows.slice(8) : []
  const rest429 = restRows.filter((r) => r.status === 429).length
  const rest403 = restRows.filter((r) => r.status === 403).length

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 3 — Missing Rate Limiting / Bot Protection</h2>
        <div className="meta">CVSS 7.5 (High) · CWE-770 / CWE-799 · A06:2025</div>
        <p>
          Sınırlı stoklu ürün (ekran kartı, 100 adet) satın alma endpoint'i frekans/adet sınırı içermez;
          tek istemci (scalper botu) tüm stoğu tüketebilir. Fix, iki bağımsız tasarım kontrolü ekler:
          rate limit + kişi başı adet limiti.
        </p>
      </header>

      <div className="actionbar">
        <button className="btn primary" onClick={run} disabled={busy}>
          {busy ? 'Gönderiliyor…' : `${N} İstek Gönder (Bot Simülasyonu)`}
        </button>
      </div>

      <div className="compare">
        {/* VULNERABLE — canlı sayaç + ilerleme çubuğu */}
        <div className={vuln?.stock === 0 ? 'panel allowed' : 'panel'}>
          <h3>Vulnerable — canlı sayaç</h3>
          {!vuln ? (
            <div className="muted">Henüz istek atılmadı.</div>
          ) : (
            <>
              <div className="statusline">
                {vuln.done}/{N} istek · geçti: <b style={{ color: '#7CFFB2' }}>{vuln.ok}</b> · reddedildi:{' '}
                <b style={{ color: '#ff9aa0' }}>{vuln.rejected}</b>
              </div>
              <div style={{ background: 'rgba(255,255,255,.08)', borderRadius: 6, overflow: 'hidden', height: 14, margin: '8px 0' }}>
                <div style={{ width: `${pct}%`, height: '100%', background: '#ff4d4f', transition: 'width .1s' }} />
              </div>
              {vuln.stock != null && (
                <>
                  <div className="statusline">kalan stok: <b style={{ color: vuln.stock === 0 ? '#ff9aa0' : '#7CFFB2' }}>{vuln.stock}</b> / 100</div>
                  {vuln.rejected === 0 && (
                    <div className="banner leak">🔓 Bot tüm stoğu tüketti — {vuln.ok}/{N} istek başarılı, hiçbiri engellenmedi.</div>
                  )}
                </>
              )}
            </>
          )}
        </div>

        {/* FIXED — istek-istek tablo */}
        <div className={fixedStock != null ? 'panel blocked' : 'panel'}>
          <h3>Fixed — istek-istek sonuç</h3>
          {!fixedRows ? (
            <div className="muted">Henüz istek atılmadı.</div>
          ) : (
            <>
              <div className="statusline">
                geçti: <b style={{ color: '#7CFFB2' }}>{fixedOk}</b> · reddedildi: <b style={{ color: '#ff9aa0' }}>{fixedRejected}</b>
              </div>
              <table style={{ width: '100%', fontSize: 13, borderCollapse: 'collapse', margin: '6px 0' }}>
                <thead>
                  <tr style={{ textAlign: 'left', color: 'var(--muted)' }}>
                    <th style={{ padding: '2px 6px' }}>#</th>
                    <th style={{ padding: '2px 6px' }}>HTTP</th>
                    <th style={{ padding: '2px 6px' }}>devreye giren kontrol</th>
                  </tr>
                </thead>
                <tbody>
                  {shownRows.map((r) => (
                    <tr key={r.i}>
                      <td style={{ padding: '2px 6px' }}>{r.i}</td>
                      <td style={{ padding: '2px 6px', color: statusColor(r.status), fontWeight: 700 }}>{r.status}</td>
                      <td style={{ padding: '2px 6px' }}>{controlLabel(r.status)}</td>
                    </tr>
                  ))}
                  {restRows.length > 0 && (
                    <tr>
                      <td style={{ padding: '2px 6px' }}>9–{N}</td>
                      <td style={{ padding: '2px 6px', color: '#ff9aa0', fontWeight: 700 }}>429×{rest429}{rest403 ? ` / 403×${rest403}` : ''}</td>
                      <td style={{ padding: '2px 6px' }}>rate limit</td>
                    </tr>
                  )}
                </tbody>
              </table>
              {fixedStock != null && (
                <>
                  <div className="statusline">kalan stok: <b style={{ color: '#7CFFB2' }}>{fixedStock}</b> / 100 (bot: {100 - fixedStock} adet)</div>
                  <div className="banner safe">🔒 Bot {100 - fixedStock} adet alabildi, gerisi engellendi (önce 403 kişi-başı, sonra 429 rate limit).</div>
                </>
              )}
            </>
          )}
        </div>
      </div>

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
