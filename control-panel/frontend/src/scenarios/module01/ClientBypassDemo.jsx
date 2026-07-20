import { useState } from 'react'
import { proxy, MODULE01 } from '../../api.js'
import { LoginBox, CompareGrid, LeakBanner, HowItWorks } from '../../ui.jsx'

const SENARYO = '03-client-side-enforcement-bypass'

const STEPS = [
  'Gerçek arayüzde "Sil" butonu Alice\'e hiç gösterilmez — yetki yalnızca istemci tarafında (butonu gizleyerek) zorlanmış.',
  'Ama butonun DOM\'da olmaması, endpoint\'in var olmadığı anlamına gelmez.',
  'Alice geçerli session\'ıyla DELETE /api/admin/users/2 isteğini doğrudan (DevTools/curl/bu buton) atabilir.',
  'Vulnerable endpoint yalnızca authentication kontrol ediyor, rol kontrolü yok → silme 200 ile gerçekleşir.',
  'Fixed sürüm aynı kuralı sunucuda uygular: role != "admin" ise 403. Güvenlik "butonu gizlemeye" değil sunucu-tarafı kontrole dayanmalı.',
]

const VULN_CODE = `@app.delete("/api/admin/users/{user_id}")
def delete_user(user_id: int, current_user: sqlite3.Row = Depends(get_current_user)):
    # ...
    conn = get_db_connection()
    target = conn.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        conn.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return {"message": f"user {target['username']} (id={user_id}) deleted"}`

const FIXED_CODE = `@app.delete("/api/admin/users/{user_id}")
def delete_user(user_id: int, current_user: sqlite3.Row = Depends(get_current_user)):
    # ...
    if current_user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")

    conn = get_db_connection()
    target = conn.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        conn.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return {"message": f"user {target['username']} (id={user_id}) deleted"}`

export default function ClientBypassDemo() {
  const [username, setUsername] = useState('alice')
  const [password, setPassword] = useState('AliceStrongPass!23')
  const [targetId, setTargetId] = useState('2')
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

  async function deleteUser() {
    setBusy(true)
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      next[v] = await proxy(v, MODULE01, SENARYO, `api/admin/users/${targetId}`, { method: 'DELETE' })
    }
    setResults(next)
    setBusy(false)
  }

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 3 — Client-Side Enforcement Bypass</h2>
        <div className="meta">CWE-602 · A01:2025 · yetki yalnızca istemci tarafında zorlanıyor</div>
        <p>
          Gerçek uygulamada "Sil" butonu Alice'e <b>hiç gösterilmez</b> (UI'da gizli). Ama yetki yalnızca
          arayüzde zorlandığından, saldırgan DevTools/curl ile API'yi doğrudan çağırabilir. Aşağıdaki buton,
          o gizli çağrıyı temsil eder: vulnerable sürüm silmeyi <code>200</code> ile gerçekleştirir, fixed
          sürüm sunucu tarafında <code>403</code> ile reddeder.
        </p>
        <div className="note">
          ⚠️ Bu buton demo amaçlı görünür kılınmıştır; normalde arayüzde bulunmaz — senaryonun özü, güvenliğin
          "butonu gizlemeye" değil sunucu-tarafı kontrole dayanması gerektiğidir.
        </div>
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
          <label>Silinecek kullanıcı ID</label>
          <input value={targetId} onChange={(e) => setTargetId(e.target.value)} style={{ width: 80 }} />
        </div>
        <button className="btn danger" onClick={deleteUser} disabled={busy}>
          Gizli admin işlemini dene: DELETE /api/admin/users/&#123;id&#125;
        </button>
      </div>

      <LeakBanner results={results} />
      <CompareGrid results={results} />

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
