import { useState } from 'react'
import { proxy, MODULE03 } from '../../api.js'
import { SimCompareGrid, HowItWorks } from '../../ui.jsx'

const SENARYO = '04-component-rce-struts-style'
const PAYLOAD = 'order total %{7*7}'

const STEPS = [
  'Uygulama, gelen veriyi işlemek için üçüncü taraf data_parser bileşenine güveniyor.',
  'POST /parse ile gönderdiğin veri doğrudan bu ayrıştırıcıya geçiyor.',
  'Zafiyetli sürüm, girdideki %{...} ifadelerini düz veri değil, "değerlendirilecek ifade" olarak ele alıyor (Struts OGNL injection deseni).',
  '%{7*7} gibi bir sonda görüldüğünde gerçek bileşen ifadeyi sunucuda çalıştırırdı (RCE); burada defanged olarak [SİMÜLASYON] metni döner.',
  'Fixed sürümde ifade değerlendirmesi tamamen kaldırılmıştır: %{...} yalnızca sıradan karakterlerdir, girdi salt veri olarak işlenir.',
]

const VULN_CODE = `_EXPRESSION_PATTERN = re.compile(r"%\\{([^}]*)\\}")


def parse(payload: str) -> dict:
    # ...
    match = _EXPRESSION_PATTERN.search(payload)
    if match:
        expression = match.group(1)
        return {
            "parsed": False,
            "rce": "[SİMÜLASYON] Bu noktada arbitrary code execution olurdu: ...",
            "input": payload,
        }

    return {"parsed": True, "value": payload}`

const FIXED_CODE = `def parse(payload: str) -> dict:
    # FIX: İfade değerlendirmesi yok. %{...} dizileri yalnızca metindir; girdi her
    # zaman salt veri olarak döndürülür.
    return {"parsed": True, "value": payload}`

export default function StrutsRceDemo() {
  const [payload, setPayload] = useState('sipariş toplam 100')
  const [results, setResults] = useState({})
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      next[v] = await proxy(v, MODULE03, SENARYO, 'parse', { method: 'POST', body: { payload } })
    }
    setResults(next)
    setBusy(false)
  }

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 4 — Component RCE / Struts tarzı</h2>
        <div className="meta">CVSS 9.8 (Critical) · CWE-1395 / CWE-477 · A03:2025 · DEFANGED simülasyon</div>
        <p>
          Kusur güvenilen <code>data_parser</code> bileşeninde: girdideki <code>{'%{...}'}</code> ifadesi
          "değerlendirildiği" için saldırgan kontrollü veri sunucuda yürütme yoluna girer (Struts OGNL injection).
          Zararsız bir değerle ve OGNL payload ile deneyip farkı görün.
        </p>
      </header>

      <div className="actionbar">
        <div className="field" style={{ flex: 1, minWidth: 280 }}>
          <label>Ayrıştırılacak veri (payload)</label>
          <input value={payload} onChange={(e) => setPayload(e.target.value)} style={{ width: '100%' }} />
        </div>
        <button className="btn" onClick={() => setPayload(PAYLOAD)} disabled={busy}>
          OGNL Payload Doldur
        </button>
        <button className="btn primary" onClick={run} disabled={busy}>
          Parse Et (iki sürüme)
        </button>
      </div>

      <SimCompareGrid results={results} />
      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
