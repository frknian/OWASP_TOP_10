import { useState } from 'react'
import { proxy, MODULE01 } from '../../api.js'
import { LoginBox, CompareGrid, LeakBanner, HowItWorks } from '../../ui.jsx'

const SENARYO = '02-missing-function-level-access-control'

const STEPS = [
  'Alice (role=user) olarak giriş yaptın; admin değilsin.',
  'GET /api/admin/users normalde yalnızca yöneticilere açık bir yönetim fonksiyonu.',
  'Vulnerable endpoint\'te ne authentication (Depends yok) ne de rol kontrolü var — fonksiyon imzası bile parametresiz: def list_all_users().',
  'Bu yüzden Alice (hatta anonim biri) tüm kullanıcıların email/balance/role verisini tek istekte çekebiliyor — dikey yetki aşımı (BFLA).',
  'Fixed sürüm hem Depends(get_current_user) ile kimlik doğrular hem de role != "admin" ise 403 döndürür.',
]

const VULN_CODE = `@app.get("/api/admin/users")
def list_all_users():
    # ...
    conn = get_db_connection()
    users = conn.execute(
        "SELECT id, username, email, balance, phone_number, role FROM users ORDER BY id"
    ).fetchall()
    conn.close()

    return [dict(user) for user in users]`

const FIXED_CODE = `@app.get("/api/admin/users")
def list_all_users(current_user: sqlite3.Row = Depends(get_current_user)):
    # ...
    if current_user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")

    conn = get_db_connection()
    users = conn.execute(
        "SELECT id, username, email, balance, phone_number, role FROM users ORDER BY id"
    ).fetchall()
    conn.close()

    return [dict(user) for user in users]`

export default function BflaDemo() {
  const [username, setUsername] = useState('alice')
  const [password, setPassword] = useState('AliceStrongPass!23')
  const [loginState, setLoginState] = useState({})
  const [results, setResults] = useState({})
  const [busy, setBusy] = useState(false)

  async function login() {
    setBusy(true)
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      const r = await proxy(v, MODULE01, SENARYO, 'login', {
        method: 'POST',
        body: { username, password },
      })
      next[v] = r.ok ? 'ok' : `hata (${r.status})`
    }
    setLoginState(next)
    setBusy(false)
  }

  async function callAdmin() {
    setBusy(true)
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      next[v] = await proxy(v, MODULE01, SENARYO, 'api/admin/users')
    }
    setResults(next)
    setBusy(false)
  }

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 2 — Missing Function Level Access Control (BFLA)</h2>
        <div className="meta">CWE-285 · A01:2025 Broken Access Control · dikey yetki yükselmesi</div>
        <p>
          <code>GET /api/admin/users</code> yalnızca admin'e açık olmalı, ama vulnerable sürüm rol
          kontrolü yapmıyor. <b>Alice (normal kullanıcı)</b> ile giriş yapıp admin endpoint'ini çağırın:
          vulnerable tüm kullanıcı listesini <code>200</code> ile döndürür, fixed <code>403</code> verir.
        </p>
      </header>

      <LoginBox
        username={username}
        password={password}
        setUsername={setUsername}
        setPassword={setPassword}
        onLogin={login}
        loginState={loginState}
        busy={busy}
      />

      <div className="actionbar">
        <button className="btn primary" onClick={callAdmin} disabled={busy}>
          GET /api/admin/users (iki sürüme)
        </button>
        <span className="tip">Alice admin değil — yine de erişebiliyor mu?</span>
      </div>

      <LeakBanner results={results} />
      <CompareGrid results={results} />

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
