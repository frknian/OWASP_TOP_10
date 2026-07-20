import { useState } from 'react'
import { proxy, MODULE09 } from '../../api.js'
import { HowItWorks } from '../../ui.jsx'

const SENARYO = '02-log-injection-forging'
const BENIGN = 'Sayfa yüklenmiyor, yardım eder misiniz?'
// Gerçek newline + sahte, meşru görünümlü sistem kaydı.
const FORGING = 'sorun var\n[ADMIN] bob tarafından yetkilendirme onaylandı: yetki=admin'

const STEPS = [
  'Log satırları newline ile ayrılır — bu, log formatının "kontrol karakteri"dir.',
  'Vulnerable: message hiç temizlenmeden log satırına gömülür; içindeki GERÇEK \\n log\'da yeni bir satır AÇAR.',
  'Saldırgan bu yeni satıra, sistemin ürettiğine benzeyen sahte bir kayıt yazar ([ADMIN] ... yetki=admin).',
  'Sonuç: tek istek → iki log kaydı. Sahte satır kendi zaman damgasıyla, gerçek bir sistem mesajından ayırt edilemez.',
  'Fixed: sanitize_for_log() ile \\n → \\\\n escape edilir; girdi tek satırda, görünür kaçış karakteri olarak kalır → forging imkânsız.',
]

const VULN_CODE = `def _log(line: str) -> None:
    # Her fiziksel satır, log listesine AYRI bir kayıt olarak eklenir
    # (gerçek log dosyası davranışı: \\n yeni satır = yeni kayıt).
    for physical_line in line.split("\\n"):
        APP_LOG.append(f"{ts} {physical_line}")

@app.post("/report-issue")
def report_issue(req: IssueRequest):
    # ZAFIYET: message hiç temizlenmeden log'a gömülüyor.
    _log(f"INFO User {req.username} reported: {req.message}")`

const FIXED_CODE = `def sanitize_for_log(value: str) -> str:
    # FIX: satır sonu/başı ve kontrol karakterlerini escape et → log forging imkânsız.
    return (
        value.replace("\\\\", "\\\\\\\\")   # önce ters bölü (kaçışların kaçışı)
        .replace("\\n", "\\\\n")
        .replace("\\r", "\\\\r")
        .replace("\\t", "\\\\t")
    )

@app.post("/report-issue")
def report_issue(req: IssueRequest):
    # FIX: username ve message log'a yazılmadan önce escape edilir.
    safe_user = sanitize_for_log(req.username)
    safe_msg = sanitize_for_log(req.message)
    _log(f"INFO User {safe_user} reported: {safe_msg}")`

function LogPanel({ title, cls, result }) {
  if (!result) {
    return (
      <div className="panel">
        <h3>{title}</h3>
        <div className="muted">Henüz istek atılmadı.</div>
      </div>
    )
  }
  const { before, after, lines } = result
  const delta = after - before
  return (
    <div className={cls}>
      <h3>
        {title} <span className="badge">+{delta} satır</span>
      </h3>
      <div className="statusline">
        log satır sayısı: {before} → <b style={{ color: delta > 1 ? '#ff9aa0' : '#7CFFB2' }}>{after}</b>{' '}
        (tek istek <b>{delta}</b> kayıt üretti)
      </div>
      <pre style={{ whiteSpace: 'pre-wrap' }}>
        {lines.map((line, i) => {
          const forged = line.includes('[ADMIN]') && !line.includes('reported:')
          return forged ? (
            <span key={i} className="keyline">{line}{'\n'}</span>
          ) : (
            <span key={i}>{line}{'\n'}</span>
          )
        })}
      </pre>
    </div>
  )
}

export default function LogInjectionDemo() {
  const [username, setUsername] = useState('bob')
  const [message, setMessage] = useState(BENIGN)
  const [vuln, setVuln] = useState(null)
  const [fixed, setFixed] = useState(null)
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    const next = {}
    for (const variant of ['vulnerable', 'fixed']) {
      // Loglar biriktiği için MUTLAK sayı değil, bu isteğin ürettiği DELTA ölçülür.
      const pre = await proxy(variant, MODULE09, SENARYO, 'logs')
      const before = pre.data?.count ?? 0
      await proxy(variant, MODULE09, SENARYO, 'report-issue', { method: 'POST', body: { username, message } })
      const post = await proxy(variant, MODULE09, SENARYO, 'logs')
      next[variant] = {
        before,
        after: post.data?.count ?? 0,
        lines: post.data?.log_lines || [],
      }
    }
    setVuln(next.vulnerable)
    setFixed(next.fixed)
    setBusy(false)
  }

  const vForged = vuln && vuln.after - vuln.before > 1
  const fBlocked = fixed && fixed.after - fixed.before === 1

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 2 — Log Injection / Forging</h2>
        <div className="meta">CVSS 5.3 (Medium) · CWE-117 · A09:2025</div>
        <p>
          <code>message</code> alanı hiç temizlenmeden log satırına gömülüyor. İçine gerçek bir newline
          konursa log'da <b>yeni bir satır açılır</b> ve saldırgan sahte, meşru görünümlü bir sistem kaydı
          enjekte eder. Fixed sürüm kontrol karakterlerini escape eder.
        </p>
        <div className="note">
          ✅ Bu senaryo <b>gerçekten çalışır</b> (defanged değil) — enjekte edilen <code>\n</code> log
          listesinde ayrı bir kayıt üretir.
        </div>
      </header>

      <div className="actionbar">
        <div className="field">
          <label>Kullanıcı adı</label>
          <input value={username} onChange={(e) => setUsername(e.target.value)} style={{ minWidth: 110 }} />
        </div>
        <div className="field" style={{ flex: 1, minWidth: 260 }}>
          <label>Mesaj</label>
          <input value={message} onChange={(e) => setMessage(e.target.value)} style={{ width: '100%' }} />
        </div>
        <button className="btn" onClick={() => setMessage(FORGING)} disabled={busy}>
          Forging Payload Doldur
        </button>
        <button className="btn primary" onClick={run} disabled={busy}>
          Gönder (iki sürüme)
        </button>
      </div>

      {message.includes('\n') && (
        <div className="note">
          Gönderilecek mesaj gerçek bir satır sonu içeriyor:{' '}
          <code>{JSON.stringify(message)}</code>
        </div>
      )}

      {vForged && (
        <div className="banner leak">
          🔓 Sahte log kaydı oluşturuldu — tek istek <b>{vuln.after - vuln.before}</b> log satırı üretti; enjekte edilen
          <code> [ADMIN] …yetki=admin</code> satırı ayrı, meşru görünümlü bir kayıt (kırmızı).
        </div>
      )}
      {fBlocked && (
        <div className="banner safe">
          🔒 Log injection engellendi — tek istek <b>1</b> log satırı üretti; <code>\n</code> görünür kaçış
          karakteri olarak tek satırda kaldı.
        </div>
      )}

      <div className="compare">
        <LogPanel title="Vulnerable — ham girdi" cls={vForged ? 'panel allowed' : 'panel'} result={vuln} />
        <LogPanel title="Fixed — sanitize_for_log()" cls={fBlocked ? 'panel blocked' : 'panel'} result={fixed} />
      </div>

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
