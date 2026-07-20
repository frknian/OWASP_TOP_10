import { useState } from 'react'
import { proxy, MODULE02 } from '../../api.js'
import { CompareGrid, ScenarioBanners, HowItWorks } from '../../ui.jsx'

const SENARYO = '02-directory-listing-source-exposure'

const STEPS = [
  'Statik dosya klasörü directory listing açık servis ediliyor: GET /files/ tüm dosyaları listeler.',
  'Saldırgan, dosya adı tahmin etmeye bile gerek kalmadan old_admin_utils.py gibi unutulmuş kaynak dosyaları görür.',
  '.py dosyası dahi ham (yorumlanmadan) düz metin döndüğü için içindeki hardcoded DB parolası ve IDOR yorumu doğrudan okunur.',
  'Fixed sürümde listing route\'u yok (GET /files/ → 404) ve dosya servisi bir whitelist ile sınırlı: yalnızca readme.txt.',
  'old_admin_utils.py diskte hâlâ dursa bile whitelist\'te olmadığı için 404 döner.',
]

const VULN_CODE = `@app.get("/files/", response_class=HTMLResponse)
def list_files():
    # ...
    entries = os.listdir(FILES_DIR)
    links = "".join(f'<li><a href="/files/{name}">{name}</a></li>' for name in sorted(entries))
    return f"<h2>Index of /files/</h2><ul>{links}</ul>"


@app.get("/files/{filename}", response_class=PlainTextResponse)
def get_file(filename: str):
    # ...
    file_path = os.path.join(FILES_DIR, filename)
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()`

const FIXED_CODE = `ALLOWED_FILES = {"readme.txt"}

# NOT: /files/ listeleme route'u kasıtlı olarak yoktur (directory listing kapalı).

@app.get("/files/{filename}", response_class=PlainTextResponse)
def get_file(filename: str):
    # ...
    if filename not in ALLOWED_FILES:
        raise HTTPException(status_code=404, detail="Not found")
    # ...
        return f.read()`

export default function DirectoryListingDemo() {
  const [filename, setFilename] = useState('old_admin_utils.py')
  const [listing, setListing] = useState({})
  const [fileResults, setFileResults] = useState({})
  const [busy, setBusy] = useState(false)

  async function listDir() {
    setBusy(true)
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      next[v] = await proxy(v, MODULE02, SENARYO, 'files/')
    }
    setListing(next)
    setBusy(false)
  }

  async function viewFile() {
    setBusy(true)
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      next[v] = await proxy(v, MODULE02, SENARYO, `files/${filename}`)
    }
    setFileResults(next)
    setBusy(false)
  }

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 2 — Directory Listing → Source Exposure</h2>
        <div className="meta">CVSS 7.5 (High) · CWE-548 (Directory Listing) / CWE-540 / CWE-798 · A02:2025</div>
        <p>
          Statik klasör directory listing ile açıkta. <code>GET /files/</code> tüm dosyaları listeler;
          <code> old_admin_utils.py</code> gibi kaynak dosyalar ham içerikle (hardcoded credential dahil)
          okunabilir. Fixed sürümde listing yoktur ve yalnızca whitelist'teki <code>readme.txt</code> servis edilir.
        </p>
      </header>

      <div className="actionbar">
        <button className="btn primary" onClick={listDir} disabled={busy}>
          Dizini Listele (iki sürüme) → GET /files/
        </button>
      </div>
      <ScenarioBanners
        results={listing}
        vulnLeakMsg="Dizin listelendi — tüm dosya adları (unutulmuş kaynaklar dahil) açığa çıktı."
        fixedBlockMsg="Listing kapalı (404) — dizin içeriği görünmüyor."
      />
      <CompareGrid results={listing} />

      <div className="actionbar" style={{ marginTop: 20 }}>
        <div className="field">
          <label>Dosya adı</label>
          <input value={filename} onChange={(e) => setFilename(e.target.value)} style={{ minWidth: 220 }} />
        </div>
        <button className="btn primary" onClick={viewFile} disabled={busy}>
          Dosyayı Görüntüle (iki sürüme)
        </button>
        <span className="tip">Deneyin: old_admin_utils.py (fixed 404) vs readme.txt (fixed 200, whitelist)</span>
      </div>
      <ScenarioBanners
        results={fileResults}
        vulnLeakMsg="Kaynak sızdı — dosya ham içerikle döndü (hardcoded credential okunabilir)."
        fixedBlockMsg="Whitelist dışı dosya erişilemez (404)."
        fixedOkMsg="Fixed: 200 — whitelist'teki dosya (readme.txt) meşru şekilde servis edildi."
      />
      <CompareGrid results={fileResults} />

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
