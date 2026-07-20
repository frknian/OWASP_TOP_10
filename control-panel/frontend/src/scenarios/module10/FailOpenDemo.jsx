import { useState } from 'react'
import { proxy, MODULE10 } from '../../api.js'
import { HowItWorks } from '../../ui.jsx'

const SENARYO = '02-fail-open-authentication'

const STEPS = [
  'Bir güvenlik kontrolü kararını veremediğinde (bağımlı servis çöktü, zaman aşımı, beklenmeyen istisna) iki olası varsayılan vardır.',
  'FAIL OPEN: "izin ver" → kesinti anında erişim kontrolü tamamen DEVRE DIŞI kalır. Güvenlik kaybedilir.',
  'FAIL SECURE: "reddet" → kesinti anında herkes reddedilir (admin dahil). Kullanılabilirlik kaybedilir, güvenlik korunur.',
  'Fail-open genelde kötü niyetle değil İYİ NİYETLE yazılır: "servis çöktü diye kullanıcıları mağdur etmeyelim". Ama erişim kontrolünde "bilmiyorum" = "HAYIR" olmalıdır.',
  'Kritik risk: saldırgan yetki servisini kendisi çökertebiliyorsa (ör. bu modülün S1\'indeki DoS ile), fail-open\'ı tetikleyerek erişim elde eder — iki zafiyet kritik bir zincire dönüşür.',
]

const VULN_CODE = `@app.get("/admin/dashboard")
def admin_dashboard(user: str | None = None):
    try:
        allowed = policy_engine_check(user)
    except PolicyEngineError as e:
        # ZAFIYET (FAIL OPEN): yetki servisi çöktüğünde erişim REDDEDİLMİYOR, İZİN VERİLİYOR.
        return {
            "access": "granted",
            "degraded_mode": True,
            "data": "GİZLİ: admin paneli verileri (tüm kullanıcılar, sistem ayarları)",
        }`

const FIXED_CODE = `@app.get("/admin/dashboard")
def admin_dashboard(user: str | None = None):
    try:
        allowed = policy_engine_check(user)
    except PolicyEngineError:
        # FIX (FAIL SECURE / CLOSED): karar verilemiyorsa erişim REDDEDİLİR.
        # İstisna detayı istemciye sızdırılmaz.
        raise HTTPException(
            status_code=503,
            detail="Yetkilendirme servisi geçici olarak kullanılamıyor — erişim reddedildi (fail-secure).",
        )
    if not allowed:
        raise HTTPException(status_code=403, detail="Admin yetkisi yok")`

function statusColor(s) {
  if (s === 200) return '#7CFFB2'
  return '#ff9aa0'
}

function Panel({ title, cls, outage, before, after }) {
  return (
    <div className={cls}>
      <h3>
        {title}{' '}
        {outage != null && (
          <span className="badge" style={{ color: outage ? '#ff9aa0' : '#7CFFB2' }}>
            {outage ? 'servis ÇÖKTÜ' : 'servis normal'}
          </span>
        )}
      </h3>
      {!before && !after ? (
        <div className="muted">Henüz istek atılmadı.</div>
      ) : (
        <>
          {before && (
            <>
              <div className="statusline">
                Kesinti ÖNCESİ, kimliksiz → <b style={{ color: statusColor(before.status) }}>HTTP {before.status}</b>
              </div>
              <pre>{JSON.stringify(before.data, null, 2)}</pre>
            </>
          )}
          {after && (
            <>
              <div className="statusline" style={{ marginTop: 8 }}>
                Kesinti SIRASINDA, kimliksiz → <b style={{ color: statusColor(after.status) }}>HTTP {after.status}</b>
              </div>
              <pre>{JSON.stringify(after.data, null, 2)}</pre>
            </>
          )}
        </>
      )}
    </div>
  )
}

export default function FailOpenDemo() {
  const [vBefore, setVBefore] = useState(null)
  const [fBefore, setFBefore] = useState(null)
  const [vAfter, setVAfter] = useState(null)
  const [fAfter, setFAfter] = useState(null)
  const [vAdmin, setVAdmin] = useState(null)
  const [fAdmin, setFAdmin] = useState(null)
  const [outage, setOutage] = useState(false)
  const [busy, setBusy] = useState(false)

  async function simulateOutage() {
    setBusy(true)
    setVAfter(null); setFAfter(null); setVAdmin(null); setFAdmin(null)
    // Kesinti öncesi referans davranış (kimliksiz)
    setVBefore(await proxy('vulnerable', MODULE10, SENARYO, 'admin/dashboard'))
    setFBefore(await proxy('fixed', MODULE10, SENARYO, 'admin/dashboard'))
    // Kesintiyi tetikle
    await proxy('vulnerable', MODULE10, SENARYO, 'simulate-outage', { method: 'POST' })
    await proxy('fixed', MODULE10, SENARYO, 'simulate-outage', { method: 'POST' })
    setOutage(true)
    setBusy(false)
  }

  async function accessAnonymously() {
    setBusy(true)
    setVAfter(await proxy('vulnerable', MODULE10, SENARYO, 'admin/dashboard'))
    setFAfter(await proxy('fixed', MODULE10, SENARYO, 'admin/dashboard'))
    // Karşılaştırma: admin kullanıcısı kesinti sırasında ne alıyor?
    setVAdmin(await proxy('vulnerable', MODULE10, SENARYO, 'admin/dashboard?user=admin'))
    setFAdmin(await proxy('fixed', MODULE10, SENARYO, 'admin/dashboard?user=admin'))
    setBusy(false)
  }

  async function restore() {
    setBusy(true)
    await proxy('vulnerable', MODULE10, SENARYO, 'restore-service', { method: 'POST' })
    await proxy('fixed', MODULE10, SENARYO, 'restore-service', { method: 'POST' })
    setOutage(false)
    setVBefore(null); setFBefore(null); setVAfter(null); setFAfter(null); setVAdmin(null); setFAdmin(null)
    setBusy(false)
  }

  const vFailOpen = vAfter?.status === 200
  const fFailSecure = fAfter?.status === 503

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 2 — Fail-Open Kimlik Doğrulama</h2>
        <div className="meta">CVSS 9.1 (Critical) · CWE-636 · A10:2025</div>
        <p>
          <code>/admin/dashboard</code> erişim kararı için bir "policy engine" çağırır. Vulnerable'da servis
          istisna fırlattığında karar <b>"izin ver"</b> olur — kesinti anında kimlik doğrulaması olmayan
          herkes admin paneline girer. Fixed sürüm <b>"reddet"</b> (fail-secure) davranır.
        </p>
      </header>

      <div className="actionbar">
        <button className="btn primary" onClick={simulateOutage} disabled={busy}>
          Servis Kesintisini Simüle Et (iki sürüme)
        </button>
        <button className="btn" onClick={accessAnonymously} disabled={busy || !outage}>
          Admin Paneline Eriş (kimliksiz)
        </button>
        <button className="btn" onClick={restore} disabled={busy || !outage}>
          Servisi Geri Getir
        </button>
      </div>

      {vFailOpen && (
        <div className="banner leak">
          🔓 FAIL-OPEN: Kesintide herkes girebildi — hiç oturum açmadan <code>HTTP 200</code> + gizli admin verisi döndü.
        </div>
      )}
      {fFailSecure && (
        <div className="banner safe">
          🔒 FAIL-SECURE: Kesintide kimse giremedi — kimliksiz istek <code>503</code>
          {fAdmin && <>, <b>admin kullanıcısı da <code>{fAdmin.status}</code></b></>}. Hizmet kaybı, yetkisiz erişime tercih edildi.
        </div>
      )}

      <div className="compare">
        <Panel title="Vulnerable — fail open" cls={vFailOpen ? 'panel allowed' : 'panel'} outage={outage} before={vBefore} after={vAfter} />
        <Panel title="Fixed — fail secure" cls={fFailSecure ? 'panel blocked' : 'panel'} outage={outage} before={fBefore} after={fAfter} />
      </div>

      {(vAdmin || fAdmin) && (
        <div className="note" style={{ marginTop: 12 }}>
          <b>Kesinti sırasında yetkili (<code>user=admin</code>) istek:</b>{' '}
          vulnerable → <b style={{ color: statusColor(vAdmin?.status) }}>HTTP {vAdmin?.status}</b>,{' '}
          fixed → <b style={{ color: statusColor(fAdmin?.status) }}>HTTP {fAdmin?.status}</b>.
          Fail-secure'un özü budur: kesintide <b>admin bile</b> geçemez.
        </div>
      )}

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
