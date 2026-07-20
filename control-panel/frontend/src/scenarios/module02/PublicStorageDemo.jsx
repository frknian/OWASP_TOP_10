import { useState } from 'react'
import { proxy, MODULE02 } from '../../api.js'
import { CompareGrid, ScenarioBanners, HowItWorks } from '../../ui.jsx'

const SENARYO = '04-public-cloud-storage-misconfiguration'

const STEPS = [
  'Bir "bucket"taki nesne (musteri_listesi.csv), hiçbir authentication/authorization olmadan servis ediliyor.',
  'Bu, gerçek dünyada bir S3 bucket\'ının "public-read" bırakılması (Block Public Access kapalı) ile birebir aynı sonucu doğurur.',
  'Nesnenin adını bilen anonim bir istemci, key olmadan tüm CSV içeriğini (müşteri PII) indirir.',
  'Fixed sürümde erişim, require_api_key dependency\'si ile korunur: X-API-Key yoksa/yanlışsa akış dosyaya inmeden 403 ile kesilir ("deny by default").',
  'Doğru X-API-Key gönderildiğinde ise nesne meşru şekilde 200 ile döner.',
]

const VULN_CODE = `@app.get("/storage/{filename}", response_class=PlainTextResponse)
def get_object(filename: str):
    # ...
    object_path = os.path.join(BUCKET_DIR, filename)
    with open(object_path, "r", encoding="utf-8") as f:
        return f.read()`

const FIXED_CODE = `VALID_API_KEY = os.environ.get("STORAGE_API_KEY", "acme-storage-key-please-rotate")


def require_api_key(x_api_key: str | None = Header(default=None)):
    # ...
    if x_api_key is None or x_api_key != VALID_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: valid X-API-Key required",
        )


@app.get("/storage/{filename}", response_class=PlainTextResponse)
def get_object(filename: str, _: None = Depends(require_api_key)):
    # ...
    object_path = os.path.join(BUCKET_DIR, filename)
    with open(object_path, "r", encoding="utf-8") as f:
        return f.read()`

export default function PublicStorageDemo() {
  const [filename, setFilename] = useState('musteri_listesi.csv')
  const [apiKey, setApiKey] = useState('')
  const [results, setResults] = useState({})
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    const headers = apiKey ? { 'X-API-Key': apiKey } : {}
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      next[v] = await proxy(v, MODULE02, SENARYO, `storage/${filename}`, { headers })
    }
    setResults(next)
    setBusy(false)
  }

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 4 — Public Cloud Storage Misconfiguration</h2>
        <div className="meta">CVSS 7.5 (High) · CWE-732 / CWE-284 / CWE-1188 · A02:2025</div>
        <p>
          Bir nesne deposu (bucket) herkese açık bırakılmış: anonim istemci, key olmadan
          <code> musteri_listesi.csv</code> içeriğini (müşteri PII) indirir. Fixed sürüm geçerli bir
          <code> X-API-Key</code> ister; anahtarsız istek <code>403</code> alır.
        </p>
        <div className="note">
          ℹ️ Gerçek bir bulut sağlayıcı yerine lokal bir dosya deposu ile simüle edilmiştir; davranış
          (public-read vs deny-by-default) S3/Azure Blob yanlış yapılandırmasıyla birebir aynıdır.
        </div>
      </header>

      <div className="actionbar">
        <div className="field">
          <label>Dosya adı</label>
          <input value={filename} onChange={(e) => setFilename(e.target.value)} style={{ minWidth: 200 }} />
        </div>
        <div className="field">
          <label>X-API-Key (opsiyonel)</label>
          <input
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder="(boş = anonim)"
            style={{ minWidth: 240 }}
          />
        </div>
        <button className="btn primary" onClick={run} disabled={busy}>
          Depoyu Sorgula (iki sürüme)
        </button>
      </div>
      <div className="tip" style={{ marginTop: -6, marginBottom: 8 }}>
        Doğru key: <code>acme-storage-key-please-rotate</code> — fixed'de bu key ile 200, boş/yanlış key ile 403.
      </div>

      <ScenarioBanners
        results={results}
        vulnLeakMsg="Herkese açık — key olmadan müşteri PII'si (CSV) indirildi."
        fixedBlockMsg="Yetkisiz (403) — geçerli X-API-Key gerekli."
        fixedOkMsg="Fixed: 200 — geçerli X-API-Key ile meşru erişim."
      />
      <CompareGrid results={results} />

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
