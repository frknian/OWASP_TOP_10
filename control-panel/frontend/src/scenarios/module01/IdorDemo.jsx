import { useState } from 'react'
import { proxy, MODULE01 } from '../../api.js'
import { LoginBox, CompareGrid, LeakBanner, HowItWorks } from '../../ui.jsx'

const SENARYO = '01-idor-horizontal-privilege-escalation'

const STEPS = [
  'Sen Alice olarak giriş yaptın; sunucu sana bir session cookie verdi.',
  "Bu cookie sadece 'sen kimsin'i (authentication) kanıtlıyor — ne yapmaya yetkin olduğunu değil.",
  'GET /api/accounts/2 isteği attığında, vulnerable sunucu yalnızca "geçerli oturumun var mı" diye baktı; "bu hesap SENİN mi" diye HİÇ bakmadı.',
  "Bu yüzden Bob'un (id=2) verisi, Alice'in oturumuyla sızdı — yatay yetki aşımı (IDOR/BOLA).",
  'Fixed sürüm, DB sorgusundan önce account_id ile oturum sahibinin id\'sini karşılaştırıp eşleşmezse 403 döndürür.',
]

const VULN_CODE = `@app.get("/api/accounts/{account_id}")
def get_account(account_id: int, current_user: sqlite3.Row = Depends(get_current_user)):
    conn = get_db_connection()
    account = conn.execute(
        "SELECT id, username, email, balance, phone_number FROM users WHERE id = ?",
        (account_id,),
    ).fetchone()
    conn.close()

    if account is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")

    return dict(account)`

const FIXED_CODE = `@app.get("/api/accounts/{account_id}")
def get_account(account_id: int, current_user: sqlite3.Row = Depends(get_current_user)):
    # ...
    if account_id != current_user["id"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to access this account")

    conn = get_db_connection()
    account = conn.execute(
        "SELECT id, username, email, balance, phone_number FROM users WHERE id = ?",
        (account_id,),
    ).fetchone()
    conn.close()

    return dict(account)`

export default function IdorDemo() {
  const [username, setUsername] = useState('alice')
  const [password, setPassword] = useState('AliceStrongPass!23')
  const [accountId, setAccountId] = useState('1')
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

  async function query() {
    setBusy(true)
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      next[v] = await proxy(v, MODULE01, SENARYO, `api/accounts/${accountId}`)
    }
    setResults(next)
    setBusy(false)
  }

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 1 — IDOR / BOLA (Horizontal Privilege Escalation)</h2>
        <div className="meta">CVSS 6.5 (Medium) · CWE-639 · A01:2025 Broken Access Control</div>
        <p>
          <code>GET /api/accounts/&#123;id&#125;</code>, path'teki hesap ID'sini oturum sahibiyle
          karşılaştırmadan döndürüyor. Alice olarak giriş yapıp <b>başka bir kullanıcının</b> ID'sini
          (örn. Bob = <b>2</b>) sorgulayın: vulnerable sürüm Bob'un verisini sızdırır, fixed sürüm
          <code>403</code> döndürür.
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
        <div className="field">
          <label>Hesap ID</label>
          <input value={accountId} onChange={(e) => setAccountId(e.target.value)} style={{ width: 80 }} />
        </div>
        <button className="btn primary" onClick={query} disabled={busy}>
          Sorgula (iki sürüme)
        </button>
        <span className="tip">İpucu: 1 = Alice (kendi), 2 = Bob (başkası)</span>
      </div>

      <LeakBanner results={results} />
      <CompareGrid results={results} />

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
