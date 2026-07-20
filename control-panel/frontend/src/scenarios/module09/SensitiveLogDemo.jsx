import { useState } from 'react'
import { proxy, MODULE09 } from '../../api.js'
import { HowItWorks } from '../../ui.jsx'

const SENARYO = '01-sensitive-data-in-logs'

const STEPS = [
  'Uygulama, login isteğinin TAM gövdesini (username VE password) log satırına yazıyor.',
  'Log dosyaları uygulamanın kendisinden daha ZAYIF korunur: ops/destek/analiz ekipleri erişir, yedeklenir, üçüncü taraf servislere (Datadog, Splunk, ELK) gönderilir.',
  'Parola log\'a bir kez yazıldığında, bu geniş yüzeyin tamamına sızmış demektir — kullanıcı parolasını değiştirse bile eski yedeklerde durur.',
  'Fixed: redact() alan ADINA göre çalışır; password/token/secret/credit_card gibi hassas alanlar [REDACTED] ile maskelenir.',
  'Log işlevini KAYBETMEZ: username, zaman ve endpoint hâlâ görünür — yalnızca gizli değer yazılmaz.',
]

const VULN_CODE = `@app.post("/login")
def login(req: LoginRequest):
    # ZAFIYET: tam request body log'a düz metin yazılıyor — password dahil.
    _log(f"INFO Login attempt: username={req.username} password={req.password}")

@app.get("/logs")
def get_logs():
    # ZAFIYET: log, redaksiyon olmadan olduğu gibi döndürülüyor → parolalar görünür.
    return {"log_lines": APP_LOG, "count": len(APP_LOG)}`

const FIXED_CODE = `SENSITIVE_FIELDS = {"password", "passwd", "pwd", "token", "secret",
                    "api_key", "credit_card", "cvv", "ssn"}

def redact(data: dict) -> dict:
    """Hassas alanları [REDACTED] ile maskeler (log'a yazmadan önce çağrılır)."""
    return {k: ("[REDACTED]" if k.lower() in SENSITIVE_FIELDS else v)
            for k, v in data.items()}

@app.post("/login")
def login(req: LoginRequest):
    # FIX: request body redaksiyondan geçirilerek loglanır — password [REDACTED] olur.
    safe = redact(req.model_dump())
    _log(f"INFO Login attempt: username={safe['username']} password={safe['password']}")`

function LogPanel({ title, cls, logs, password }) {
  if (!logs) {
    return (
      <div className="panel">
        <h3>{title}</h3>
        <div className="muted">Henüz istek atılmadı.</div>
      </div>
    )
  }
  const lines = logs.data?.log_lines || []
  return (
    <div className={cls}>
      <h3>
        {title} <span className="badge">{logs.data?.count ?? lines.length} satır</span>
      </h3>
      <pre style={{ whiteSpace: 'pre-wrap' }}>
        {lines.map((line, i) => {
          const leaked = password && line.includes(password)
          const redacted = line.includes('[REDACTED]')
          if (leaked) return <span key={i} className="keyline">{line}{'\n'}</span>
          if (redacted) {
            return (
              <span key={i} style={{ background: 'rgba(124,255,178,.18)', color: '#c9ffe0', display: 'block', margin: '0 -12px', padding: '0 12px' }}>
                {line}{'\n'}
              </span>
            )
          }
          return <span key={i}>{line}{'\n'}</span>
        })}
      </pre>
    </div>
  )
}

export default function SensitiveLogDemo() {
  const [username, setUsername] = useState('alice')
  const [password, setPassword] = useState('SuperSecret123')
  const [vLogs, setVLogs] = useState(null)
  const [fLogs, setFLogs] = useState(null)
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    // Vulnerable: login → logs
    await proxy('vulnerable', MODULE09, SENARYO, 'login', { method: 'POST', body: { username, password } })
    setVLogs(await proxy('vulnerable', MODULE09, SENARYO, 'logs'))
    // Fixed: login → logs
    await proxy('fixed', MODULE09, SENARYO, 'login', { method: 'POST', body: { username, password } })
    setFLogs(await proxy('fixed', MODULE09, SENARYO, 'logs'))
    setBusy(false)
  }

  const vLeaked = vLogs?.data?.log_lines?.some((l) => l.includes(password))
  const fRedacted = fLogs?.data?.log_lines?.some((l) => l.includes('[REDACTED]'))

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 1 — Loglara Hassas Veri Sızması</h2>
        <div className="meta">CVSS 6.5 (Medium) · CWE-532 · A09:2025</div>
        <p>
          <code>POST /login</code> her denemede request body'yi (username <b>ve password düz metin</b>) log
          satırına yazar. <code>GET /logs</code> bu log'u döndürdüğünde parolalar açıkça görünür. Fixed sürüm
          hassas alanları yazma anında <code>[REDACTED]</code> ile maskeler.
        </p>
      </header>

      <div className="actionbar">
        <div className="field">
          <label>Kullanıcı adı</label>
          <input value={username} onChange={(e) => setUsername(e.target.value)} style={{ minWidth: 130 }} />
        </div>
        <div className="field">
          <label>Parola</label>
          <input value={password} onChange={(e) => setPassword(e.target.value)} style={{ minWidth: 170 }} />
        </div>
        <button className="btn primary" onClick={run} disabled={busy}>
          {busy ? 'Gönderiliyor…' : 'Giriş Yap (iki sürüme)'}
        </button>
      </div>

      {vLeaked && (
        <div className="banner leak">
          🔓 Parola loglarda düz metin — <code>{password}</code> log satırında açıkça okunuyor (kırmızı satır).
        </div>
      )}
      {fRedacted && (
        <div className="banner safe">
          🔒 Hassas alan maskelendi — fixed sürümde <code>password=[REDACTED]</code>, <code>username</code> korundu (log hâlâ faydalı).
        </div>
      )}

      <div className="compare">
        <LogPanel title="Vulnerable — redaksiyon yok" cls={vLeaked ? 'panel allowed' : 'panel'} logs={vLogs} password={password} />
        <LogPanel title="Fixed — redact() uygulanıyor" cls={fRedacted ? 'panel blocked' : 'panel'} logs={fLogs} password={password} />
      </div>

      <div className="note" style={{ marginTop: 12 }}>
        ℹ️ Bu senaryoda <code>/reset</code> endpoint'i yoktur — loglar birikir (gerçek log davranışı).
        Temiz bir başlangıç için senaryoyu panelden durdurup yeniden başlatabilirsiniz.
      </div>

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
