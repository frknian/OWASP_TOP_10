import { useState } from 'react'
import { proxy, MODULE04 } from '../../api.js'
import { ResultPanel, ScenarioBanners, HowItWorks } from '../../ui.jsx'

const SENARYO = '02-hardcoded-encryption-key'

const STEPS = [
  'Uygulama "özel notları" Fernet ile DOĞRU şekilde şifreliyor — kusur algoritmada değil, anahtar yönetiminde.',
  'Vulnerable sürümde şifreleme anahtarı kaynak kodun içine gömülü (_HARDCODED_SECRET).',
  'Unutulmuş GET /source-leak endpoint\'i main.py\'nin kaynağını döndürüyor; saldırgan anahtarı bu satırdan çıkarır.',
  'Anahtar ele geçince şifreleme anlamsızdır: tüm ciphertext (geçmiş + gelecek) çözülebilir. Simetrik şifrelemenin tüm güvenliği anahtarın gizliliğine bağlıdır.',
  'Fixed sürümde /source-leak kaldırılmış (404) ve anahtar ENCRYPTION_KEY ortam değişkeninden yüklenir — kaynak sızsa bile anahtar orada yoktur.',
]

const VULN_CODE = `# ZAFIYET (CWE-321): Anahtar kaynak koda GÖMÜLÜ.
_HARDCODED_SECRET = b"hardcoded-demo-key-32-bytes-lo!!"  # tam 32 bayt
ENCRYPTION_KEY = base64.urlsafe_b64encode(_HARDCODED_SECRET)
fernet = Fernet(ENCRYPTION_KEY)


@app.get("/source-leak", response_class=PlainTextResponse)
def source_leak():
    # ZAFIYET: Uygulamanın kaynak kodunu dışarı verir. _HARDCODED_SECRET burada görünür.
    return Path(__file__).read_text(encoding="utf-8")`

const FIXED_CODE = `def _load_fernet() -> Fernet:
    # FIX (CWE-321): Anahtar ortamdan gelir; kaynak kodda hiçbir sabit sır yok.
    key = os.environ.get("ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("ENCRYPTION_KEY environment variable is required ...")
    return Fernet(key.encode("utf-8"))

# NOT: /source-leak endpoint'i BİLİNÇLİ olarak yoktur → 404.`

// Kaynak kodda anahtar/sır içeren satırları vurgula.
function isKeyLine(line) {
  return /_HARDCODED_SECRET|ENCRYPTION_KEY|SECRET|Fernet\(/.test(line)
}

function SourcePanel({ result }) {
  if (!result) {
    return (
      <div className="panel">
        <h3>Vulnerable</h3>
        <div className="muted">Henüz istek atılmadı.</div>
      </div>
    )
  }
  const source = typeof result.data === 'string' ? result.data : JSON.stringify(result.data, null, 2)
  const lines = source.split('\n')
  return (
    <div className="panel allowed">
      <h3>
        Vulnerable <span className="badge">🔓 Kaynak sızdı</span>
      </h3>
      <div className="statusline">HTTP {result.status}</div>
      <pre>
        {lines.map((ln, i) => (
          <div key={i} className={isKeyLine(ln) ? 'keyline' : undefined}>
            {ln || ' '}
          </div>
        ))}
      </pre>
    </div>
  )
}

export default function HardcodedKeyDemo() {
  const [results, setResults] = useState({})
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      next[v] = await proxy(v, MODULE04, SENARYO, 'source-leak')
    }
    setResults(next)
    setBusy(false)
  }

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 2 — Hardcoded Encryption Key</h2>
        <div className="meta">CVSS 7.5 (High) · CWE-321 / CWE-798 · A04:2025</div>
        <p>
          Şifreleme doğru (Fernet), ama anahtar kaynak koda gömülü. <code>GET /source-leak</code> kaynağı
          döndürünce anahtar satırı açığa çıkar (aşağıda vurgulu). Fixed sürümde endpoint yoktur (<code>404</code>)
          ve anahtar ortam değişkeninden gelir.
        </p>
      </header>

      <div className="actionbar">
        <button className="btn primary" onClick={run} disabled={busy}>
          Kaynak Kodu Sız (iki sürüme) → GET /source-leak
        </button>
      </div>

      <ScenarioBanners
        results={results}
        vulnLeakMsg="Anahtar açıkta — kaynak koddaki _HARDCODED_SECRET satırı okunabilir."
        fixedBlockMsg="Kaynak sızıntısı kapatılmış (404) — anahtar env'den yüklenir."
      />
      <div className="compare">
        <SourcePanel result={results.vulnerable} />
        <ResultPanel title="Fixed" result={results.fixed} />
      </div>

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
