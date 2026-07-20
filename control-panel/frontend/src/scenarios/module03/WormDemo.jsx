import { useState } from 'react'
import { proxy, MODULE03 } from '../../api.js'
import { SimCompareGrid, HowItWorks } from '../../ui.jsx'

const SENARYO = '03-postinstall-worm-shai-hulud-style'

const STEPS = [
  'Uygulama, ele geçirilmiş awesome_utils paketine bağımlı.',
  'Paketin zararlı mantığı bir REQUEST anında değil, UYGULAMA BAŞLARKEN (FastAPI lifespan / post-install) otomatik çalışır.',
  'Yani hiçbir kullanıcı etkileşimi olmadan; uygulamayı kurmak/çalıştırmak yeterli. Bir worm\'un asıl tehlikesi budur.',
  'Startup\'ta (defanged): ortam sırları "toplanır", uzak C2\'ye "gönderilir", worm diğer paketlere "yayılır" — hepsi simülasyon, gerçek ağ/dosya sızıntısı yok. Tek somut çıktı lokal bir demo dosyası.',
  'GET /status bu startup çıktısını gösterir. Fixed sürümde temiz paket kullanılır: startup\'ta hiçbir gizli davranış çalışmaz, postinstall_simulation = null.',
]

const VULN_CODE = `# vulnerable/main.py — lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # ZAFIYET: Bağımlılığın post-install/worm kodu, uygulama başlar başlamaz çalışıyor.
    _STARTUP_REPORT["postinstall_output"] = awesome_utils.run_postinstall()
    yield

# awesome_utils/__init__.py — run_postinstall (defanged)
def run_postinstall() -> str:
    # ... (env sırları "toplanır", C2'ye "gönderilir", worm "yayılır" — hepsi simülasyon)
    _DEMO_EXFIL_FILE.write_text(report, encoding="utf-8")
    return report`

const FIXED_CODE = `# fixed/main.py — lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # FIX: Başlangıçta zararlı/gizli hiçbir şey çalışmıyor. Temiz paket sessizce yüklenir.
    yield`

export default function WormDemo() {
  const [results, setResults] = useState({})
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      next[v] = await proxy(v, MODULE03, SENARYO, 'status')
    }
    setResults(next)
    setBusy(false)
  }

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 3 — Post-install Worm / Shai-Hulud tarzı</h2>
        <div className="meta">CVSS 9.8 (Critical) · CWE-1395 / CWE-506 · A03:2025 · DEFANGED simülasyon</div>
        <p>
          Bu senaryonun tehlikesi bir isteğe bağlı değil: zararlı davranış <b>uygulama başlarken</b>
          (startup/lifespan), hiçbir kullanıcı etkileşimi olmadan tetiklenir. Aşağıdaki <code>GET /status</code>,
          vulnerable sürümde startup'ta çalışmış olan simülasyon çıktısını gösterir; fixed sürümde ise temizdir.
        </p>
        <div className="note">
          ⚠️ Panel bu backend'i ilk istekte başlattığında, vulnerable sürümün post-install simülasyonu o anda
          (startup'ta) çalışır — istek yalnızca sonucu okur. Fixed sürümde startup'ta hiçbir yan etki yoktur.
        </div>
      </header>

      <div className="actionbar">
        <button className="btn primary" onClick={run} disabled={busy}>
          Durumu Sorgula (iki sürüme) → GET /status
        </button>
      </div>

      <SimCompareGrid results={results} />
      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
