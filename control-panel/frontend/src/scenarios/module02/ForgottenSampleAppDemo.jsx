import { useState } from 'react'
import { proxy, MODULE02 } from '../../api.js'
import { CompareGrid, ScenarioBanners, HowItWorks } from '../../ui.jsx'

const SENARYO = '01-forgotten-sample-app-default-credentials'

const STEPS = [
  'Uygulamanın ilk kurulumundan kalma bir "örnek yönetim paneli" (/sample-admin) üretime taşınmış ve kaldırılmamış.',
  'Panel, kaynak koda gömülü fabrika ayarı admin/admin ile korunuyor — kimse değiştirmemiş.',
  'Saldırgan bu iyi bilinen varsayılanı deneyerek (hiçbir önceden yetki gerekmeden) panele girer.',
  'Panel, keşif değeri yüksek sistem bilgisi döndürür: Python/FastAPI sürümü, OS, hostname — bilinen CVE eşlemesi için fingerprint.',
  'Fixed sürümde /sample-admin route\'u tamamen kaldırılmıştır → istek 404 alır, saldırılacak panel kalmaz.',
]

const VULN_CODE = `@app.post("/sample-admin")
def sample_admin_login(request: Request, username: str = Form(...), password: str = Form(...)):
    # ...
    if username == "admin" and password == "admin":
        # ...
        return JSONResponse(
            {
                "message": "Welcome to the Acme setup panel",
                "system_info": {
                    "python_version": platform.python_version(),
                    "fastapi_version": fastapi.__version__,
                    "os": f"{platform.system()} {platform.release()}",
                    "hostname": platform.node(),
                },
            }
        )
    return JSONResponse({"detail": "Invalid credentials"}, status_code=401)`

const FIXED_CODE = `@app.get("/")
def index():
    # Yalnızca asıl uygulama ayakta kalıyor; kurulum paneli üretim yapısından çıkarıldı.
    return {"app": "Acme Widgets API", "status": "running"}


# NOT: /sample-admin route'u (form + login) burada kasıtlı olarak yoktur.
# Kaldırılan endpoint = ortadan kalkan saldırı yüzeyi. Varsayılan kimlik bilgisi
# kontrolü, gömülü admin/admin parolası ve system-info sızıntısı artık mevcut değil.`

export default function ForgottenSampleAppDemo() {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('admin')
  const [results, setResults] = useState({})
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      next[v] = await proxy(v, MODULE02, SENARYO, 'sample-admin', {
        method: 'POST',
        form: { username, password },
      })
    }
    setResults(next)
    setBusy(false)
  }

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 1 — Forgotten Sample App / Default Credentials</h2>
        <div className="meta">CVSS 5.3 (Medium) · CWE-1392 (Default Credentials) / CWE-489 · A02:2025</div>
        <p>
          Kurulumdan kalma <code>/sample-admin</code> paneli üretimde unutulmuş ve sabit
          <b> admin/admin</b> ile korunuyor. Varsayılan kimlikle giriş deneyin: vulnerable sürüm
          sistem bilgisini sızdırır, fixed sürümde endpoint yoktur (<code>404</code>).
        </p>
      </header>

      <div className="actionbar">
        <div className="field">
          <label>Kullanıcı adı</label>
          <input value={username} onChange={(e) => setUsername(e.target.value)} />
        </div>
        <div className="field">
          <label>Parola</label>
          <input value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        <button className="btn primary" onClick={run} disabled={busy}>
          Kurulum Paneline Giriş Dene (iki sürüme)
        </button>
      </div>

      <ScenarioBanners
        results={results}
        vulnLeakMsg="Panel açıkta — varsayılan admin/admin ile sistem bilgisi (sürüm/OS/hostname) sızdı."
        fixedBlockMsg="Endpoint kaldırılmış (404) — saldırılacak panel yok."
      />
      <CompareGrid results={results} />

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
