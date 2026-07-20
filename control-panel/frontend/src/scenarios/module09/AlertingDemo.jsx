import { useState } from 'react'
import { proxy, MODULE09 } from '../../api.js'
import { HowItWorks } from '../../ui.jsx'

const SENARYO = '03-missing-alerting-threshold'
const ATTEMPTS = 5
const TARGET = 'alice'

const STEPS = [
  'Bu senaryonun konusu LOGLAMA DEĞİL — loglama her iki sürümde de aynı şekilde çalışır.',
  'Vulnerable: başarısız denemeler loglanır ama hiçbir EŞİK mantığı yoktur; /alerts kaç deneme olursa olsun HER ZAMAN boştur.',
  'Veri toplanıyor ama harekete dönüşmüyor — saldırı kayda geçse de kimse haberdar olmuyor.',
  'Fixed: kullanıcı bazlı kayan pencere (60 sn) sayacı; 5+ başarısız denemede brute_force_suspected alert objesi üretilir.',
  'OWASP 2021→2025 isim değişikliği tam da bunu vurgular: "Monitoring" (pasif izleme) → "Alerting" (aktif tepki). "Great logging with no alerting is of minimal value."',
]

const VULN_CODE = `@app.post("/login")
def login(req: LoginRequest):
    # Başarısız deneme loglanıyor (loglama VAR)...
    _log(f"WARN Failed login for username={req.username}")
    # ...ama hiçbir eşik kontrolü / alert üretimi YOK (alerting eksik).

@app.get("/alerts")
def get_alerts():
    # ZAFIYET: eşik mantığı olmadığından bu liste HER ZAMAN boştur.
    return {"alerts": [], "count": 0, ...}`

const FIXED_CODE = `ALERT_THRESHOLD = 5          # pencere içinde bu kadar başarısız deneme → alert
ALERT_WINDOW_SECONDS = 60    # kayan pencere

@app.post("/login")
def login(req: LoginRequest):
    _log(f"WARN Failed login for username={req.username}")     # loglama AYNI

    # ...ARTI eşik mantığı: kayan pencerede başarısız denemeleri say.
    attempts = [t for t in FAILED_ATTEMPTS.get(req.username, []) if t > now - ALERT_WINDOW_SECONDS]
    attempts.append(now); FAILED_ATTEMPTS[req.username] = attempts

    if len(attempts) >= ALERT_THRESHOLD:
        already = any(a["username"] == req.username and a["type"] == "brute_force_suspected" for a in ALERTS)
        if not already:                                        # dedup: alert fatigue önleme
            ALERTS.append({"type": "brute_force_suspected", "username": req.username,
                           "attempt_count": len(attempts), ...})`

function AttemptList({ rows }) {
  if (!rows.length) return null
  return (
    <ol className="steps">
      {rows.map((r) => (
        <li key={r.i}>
          deneme {r.i} → <b style={{ color: '#ff9aa0' }}>HTTP {r.status}</b>
          {r.alertCreated != null && (
            <>
              {' '}· alert: <b style={{ color: r.alertCreated ? '#7CFFB2' : 'var(--muted)' }}>{r.alertCreated ? 'OLUŞTU ✅' : 'yok'}</b>
            </>
          )}
        </li>
      ))}
    </ol>
  )
}

function Panel({ title, cls, rows, alerts }) {
  return (
    <div className={cls}>
      <h3>{title}</h3>
      {!rows.length ? (
        <div className="muted">Henüz deneme yapılmadı.</div>
      ) : (
        <>
          <AttemptList rows={rows} />
          {alerts && (
            <>
              <div className="statusline" style={{ marginTop: 8 }}>
                GET /alerts → <b style={{ color: (alerts.data?.count ?? 0) > 0 ? '#7CFFB2' : '#ff9aa0' }}>
                  {alerts.data?.count ?? 0} alert
                </b>
              </div>
              <pre>{JSON.stringify(alerts.data, null, 2)}</pre>
            </>
          )}
        </>
      )}
    </div>
  )
}

export default function AlertingDemo() {
  const [vRows, setVRows] = useState([])
  const [fRows, setFRows] = useState([])
  const [vAlerts, setVAlerts] = useState(null)
  const [fAlerts, setFAlerts] = useState(null)
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    setVRows([]); setFRows([]); setVAlerts(null); setFAlerts(null)

    // --- VULNERABLE: 5 başarısız deneme, canlı sayaç ---
    const v = []
    for (let i = 1; i <= ATTEMPTS; i++) {
      const r = await proxy('vulnerable', MODULE09, SENARYO, 'login', {
        method: 'POST', body: { username: TARGET, password: `wrong${i}` },
      })
      v.push({ i, status: r.status })
      setVRows([...v])
    }
    setVAlerts(await proxy('vulnerable', MODULE09, SENARYO, 'alerts'))

    // --- FIXED: reset ile deterministik başlangıç, sonra aynı 5 deneme ---
    await proxy('fixed', MODULE09, SENARYO, 'reset', { method: 'POST' })
    const f = []
    for (let i = 1; i <= ATTEMPTS; i++) {
      const r = await proxy('fixed', MODULE09, SENARYO, 'login', {
        method: 'POST', body: { username: TARGET, password: `wrong${i}` },
      })
      f.push({ i, status: r.status, alertCreated: r.data?.alert_created })
      setFRows([...f])
    }
    setFAlerts(await proxy('fixed', MODULE09, SENARYO, 'alerts'))

    setBusy(false)
  }

  const vSilent = vAlerts && (vAlerts.data?.count ?? 0) === 0
  const fAlerted = fAlerts && (fAlerts.data?.count ?? 0) > 0

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 3 — Alerting Eksikliği (Loglanıyor Ama Alarm Yok)</h2>
        <div className="meta">CVSS 5.3 (Medium) · CWE-778 · A09:2025</div>
        <p>
          Başarısız login denemeleri <b>her iki sürümde de loglanır</b> — fark yalnızca <b>alerting</b>
          katmanındadır. Vulnerable'da hiçbir eşik yoktur, <code>/alerts</code> hep boştur; fixed'de 60 sn
          içinde 5+ deneme bir <code>brute_force_suspected</code> alarmı üretir.
        </p>
      </header>

      <div className="actionbar">
        <button className="btn primary" onClick={run} disabled={busy}>
          {busy ? 'Deneniyor…' : `${ATTEMPTS} Başarısız Login Dene (iki sürüme)`}
        </button>
      </div>

      {vSilent && (
        <div className="banner leak">
          🔓 Saldırı sessiz kaldı — hiç alarm yok. {ATTEMPTS} başarısız deneme loglandı ama <code>/alerts</code> boş
          döndü; kimse/hiçbir şey haberdar olmadı.
        </div>
      )}
      {fAlerted && (
        <div className="banner safe">
          🔒 Eşik aşıldı, alarm oluştu — <code>brute_force_suspected</code> ({fAlerts.data.alerts[0]?.attempt_count} deneme /{' '}
          {fAlerts.data.alerts[0]?.window_seconds} sn). Toplanan veri harekete dönüştü.
        </div>
      )}

      <div className="compare">
        <Panel title="Vulnerable — eşik/alert yok" cls={vSilent ? 'panel allowed' : 'panel'} rows={vRows} alerts={vAlerts} />
        <Panel title="Fixed — eşik + alert üretimi" cls={fAlerted ? 'panel blocked' : 'panel'} rows={fRows} alerts={fAlerts} />
      </div>

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
