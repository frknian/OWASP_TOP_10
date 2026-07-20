import { useState } from 'react'
import { proxy, MODULE02 } from '../../api.js'
import { CompareGrid, HowItWorks } from '../../ui.jsx'

const SENARYO = '03-verbose-error-messages'

const STEPS = [
  'Endpoint item_id\'yi str alıp doğrudan int()\'e veriyor; "abc" gibi sayısal olmayan değerde ValueError fırlar ve yakalanmaz.',
  'Vulnerable exception handler, beklenmeyen hatada istemciye tam iç detay döndürür.',
  'traceback.format_exc() → dosya yolları, satır numaraları, iç fonksiyon adları sızar.',
  'Kütüphane sürümleri (fastapi/starlette/pydantic/uvicorn) da yanıtta döner → bilinen CVE eşlemesi için hediye.',
  'Fixed sürümde aynı hata olur ama handler detayı yalnızca sunucu log\'una yazar; istemci sadece {"detail": "Internal server error"} alır.',
]

const VULN_CODE = `@app.get("/api/process/{item_id}")
def process_item(item_id: str):
    # ...
    numeric_id = int(item_id)
    return {"item_id": numeric_id, "status": "processed"}


@app.exception_handler(Exception)
async def verbose_exception_handler(request: Request, exc: Exception):
    # ...
    return JSONResponse(
        status_code=500,
        content={
            "error": str(exc),
            "exception_type": type(exc).__name__,
            "traceback": traceback.format_exc(),
            "dependencies": _dependency_versions(),
        },
    )`

const FIXED_CODE = `@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Fix: Detaylar yalnızca sunucu log'una. logger.exception(...) tam stack trace'i
    # console'a yazar (destek/geliştirme için); istemci ise ayrıntısız jenerik yanıt alır.
    logger.exception("Unhandled error while processing %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )`

export default function VerboseErrorDemo() {
  const [itemId, setItemId] = useState('abc')
  const [results, setResults] = useState({})
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      next[v] = await proxy(v, MODULE02, SENARYO, `api/process/${itemId}`)
    }
    setResults(next)
    setBusy(false)
  }

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 3 — Verbose Error Messages</h2>
        <div className="meta">CVSS 5.3 (Medium) · CWE-209 (Sensitive Info in Error) · A02:2025</div>
        <p>
          Sayısal olmayan bir <code>item_id</code> (örn. <b>abc</b>) yakalanmayan bir <code>ValueError</code>
          tetikler. Vulnerable sürüm yanıtta tam stack trace + kütüphane sürümlerini döndürür; fixed sürüm
          aynı hatada yalnızca jenerik <code>{'{'}"detail": "Internal server error"{'}'}</code> verir.
        </p>
      </header>

      <div className="actionbar">
        <div className="field">
          <label>item_id</label>
          <input value={itemId} onChange={(e) => setItemId(e.target.value)} style={{ width: 120 }} />
        </div>
        <button className="btn primary" onClick={run} disabled={busy}>
          İşlemi Çalıştır (iki sürüme)
        </button>
        <span className="tip">Sayısal olmayan değer hatayı tetikler; sayı (örn. 42) başarılı döner.</span>
      </div>

      {results.vulnerable &&
        (results.vulnerable.status === 500 ? (
          <div className="banner leak">🔓 İç detaylar sızdı — stack trace + kütüphane sürümleri yanıtta.</div>
        ) : (
          <div className="banner neutral">Vulnerable: HTTP {results.vulnerable.status} (hata tetiklenmedi)</div>
        ))}
      {results.fixed &&
        (results.fixed.status === 500 ? (
          <div className="banner safe">🔒 Detay gizlendi — istemci yalnızca jenerik hata mesajı aldı.</div>
        ) : (
          <div className="banner neutral">Fixed: HTTP {results.fixed.status} (hata tetiklenmedi)</div>
        ))}
      <CompareGrid results={results} />

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
