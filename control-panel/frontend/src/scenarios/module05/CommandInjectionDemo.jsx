import { useState } from 'react'
import { proxy, MODULE05 } from '../../api.js'
import { SimCompareGrid, HowItWorks } from '../../ui.jsx'

const SENARYO = '03-os-command-injection-defanged'
const PAYLOAD = 'example.com; cat /etc/passwd'

const STEPS = [
  'Endpoint, domain değerini bir kabuk komutuna string olarak gömüyor: f"nslookup {domain}".',
  'Girdi kabuk tarafından yorumlanacağından, ; | && gibi metakarakterlerle ek komut enjekte edilebilir.',
  'example.com; cat /etc/passwd → oluşan komut "nslookup example.com; cat /etc/passwd" olur; kabuk ikinci komutu da çalıştırırdı.',
  'DEFANGED: gerçek komut çalıştırılmaz — vulnerable sürüm yalnızca oluşan tam komutu [SİMÜLASYON] olarak gösterir.',
  'Fixed sürüm domain\'i ^[a-zA-Z0-9.-]+$ allowlist regex\'iyle doğrular; metakarakterli girdi 400 ile reddedilir, komut hiç kurulmaz.',
]

const VULN_CODE = `@app.post("/diagnose")
def diagnose(req: DiagnoseRequest):
    # ZAFIYET: domain komut string'ine gömülüyor. (DEFANGED — gerçekte çalıştırılmaz)
    command = f"nslookup {req.domain}"
    return {
        "simulation": f"[SİMÜLASYON] Bu komut çalıştırılırdı: {command}",
        "built_command": command,
        ...
    }`

const FIXED_CODE = `_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.-]+$")  # allowlist

@app.post("/diagnose")
def diagnose(req: DiagnoseRequest):
    # FIX: Strict allowlist. Uymayan girdi hiç işlenmeden 400 döner.
    if not _DOMAIN_RE.match(req.domain):
        raise HTTPException(status_code=400, detail="Geçersiz domain: yalnızca [a-zA-Z0-9.-] izinli")
    return {"safe": f"[GÜVENLİ] Doğrulanmış domain: {req.domain}, komut hiç oluşturulmadı."}`

export default function CommandInjectionDemo() {
  const [domain, setDomain] = useState('example.com')
  const [results, setResults] = useState({})
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      next[v] = await proxy(v, MODULE05, SENARYO, 'diagnose', { method: 'POST', body: { domain } })
    }
    setResults(next)
    setBusy(false)
  }

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 3 — OS Command Injection (DEFANGED)</h2>
        <div className="meta">CVSS 9.8 (Critical, defanged) · CWE-78 · A05:2025</div>
        <p>
          <code>domain</code> bir kabuk komutuna gömülüyor. Metakarakterlerle (<code>;</code>) ek komut
          enjekte edilebilir. Fixed sürüm allowlist regex ile doğrular ve metakarakterli girdiyi{' '}
          <code>400</code> ile reddeder.
        </p>
        <div className="note">
          ⚠️ DEFANGED: gerçek komut hiçbir sürümde çalıştırılmaz. Vulnerable yalnızca oluşan komutu gösterir.
        </div>
      </header>

      <div className="actionbar">
        <div className="field" style={{ flex: 1, minWidth: 280 }}>
          <label>Domain</label>
          <input value={domain} onChange={(e) => setDomain(e.target.value)} style={{ width: '100%' }} />
        </div>
        <button className="btn" onClick={() => setDomain(PAYLOAD)} disabled={busy}>
          Enjeksiyon Payload'ı Doldur
        </button>
        <button className="btn primary" onClick={run} disabled={busy}>
          Diagnose (iki sürüme)
        </button>
      </div>

      <SimCompareGrid results={results} />
      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
