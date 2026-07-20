import { useState } from 'react'
import { proxy, MODULE07 } from '../../api.js'
import { HowItWorks } from '../../ui.jsx'

const SENARYO = '01-credential-stuffing-no-protection'
// carol'un gerçek parolası (Password1) bilinçli olarak listenin SONUNDA — koruma
// olmadığında 12. denemede engelsiz bulunur, korumayla hiç sıraya giremez.
const PASSWORDS = [
  '123456', 'password', 'qwerty123', 'letmein1', 'Welcome1', 'Admin123',
  'Iloveyou1', 'Sunshine1', 'Football1', 'Monkey123', 'Dragon123', 'Password1',
]

const STEPS = [
  'Hashing DOĞRUdur (argon2id) — kusur parolanın nasıl saklandığında değil, kaç kez denenebildiğinde.',
  'Vulnerable: deneme sayacı/gecikme/kilitleme YOK. Saldırgan tek kullanıcıya karşı sınırsız parola dener.',
  'carol yaygın bir parola (Password1) kullanır; sınırsız deneme hakkıyla bu istatistiksel olarak bulunur.',
  'Fixed: kullanıcı bazlı başarısız deneme sayacı; 5 denemeden sonra 30 sn kilitleme (429 + Retry-After).',
  'Kilitliyken doğru parola bile reddedilir — saldırgana "doğru buldun ama zamanlama yanlış" bilgisi verilmez.',
]

const VULN_CODE = `@app.post("/login")
def login(req: LoginRequest):
    # ZAFIYET: deneme sayacı, gecikme veya kilitleme YOK.
    user = USERS.get(req.username)
    try:
        password_hasher.verify(user["password_hash"], req.password)
    except VerifyMismatchError:
        raise HTTPException(401, "Geçersiz kullanıcı adı veya parola")
    return {"authenticated": True, ...}`

const FIXED_CODE = `@app.post("/login")
def login(req: LoginRequest):
    entry = ATTEMPTS.setdefault(req.username, {"failed_count": 0, "locked_until": None})
    if entry["locked_until"] and time.time() < entry["locked_until"]:
        raise HTTPException(429, {...}, headers={"Retry-After": ...})   # kilitliyken parola BAKILMAZ
    ...
    if not password_ok:
        entry["failed_count"] += 1
        if entry["failed_count"] >= MAX_ATTEMPTS:            # 5
            entry["locked_until"] = time.time() + LOCKOUT_SECONDS   # 30 sn
            raise HTTPException(429, "...hesap geçici kilitlendi")`

function statusColor(s) {
  if (s >= 200 && s < 300) return '#7CFFB2'
  return '#ff9aa0'
}
function controlLabel(status) {
  if (status === 200) return '✅ giriş başarılı'
  if (status === 401) return 'yanlış parola'
  if (status === 429) return '🔒 kilitli'
  return ''
}

function AttemptTable({ title, rows, cls }) {
  return (
    <div className={cls}>
      <h3>{title}</h3>
      {rows.length === 0 ? (
        <div className="muted">Henüz deneme yapılmadı.</div>
      ) : (
        <table style={{ width: '100%', fontSize: 13, borderCollapse: 'collapse', margin: '6px 0' }}>
          <thead>
            <tr style={{ textAlign: 'left', color: 'var(--muted)' }}>
              <th style={{ padding: '2px 6px' }}>#</th>
              <th style={{ padding: '2px 6px' }}>parola</th>
              <th style={{ padding: '2px 6px' }}>HTTP</th>
              <th style={{ padding: '2px 6px' }}>durum</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.i}>
                <td style={{ padding: '2px 6px' }}>{r.i}</td>
                <td style={{ padding: '2px 6px', fontFamily: 'monospace' }}>{r.password}</td>
                <td style={{ padding: '2px 6px', color: statusColor(r.status), fontWeight: 700 }}>{r.status}</td>
                <td style={{ padding: '2px 6px' }}>{controlLabel(r.status)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

export default function CredentialStuffingDemo() {
  const [username, setUsername] = useState('carol')
  const [vulnRows, setVulnRows] = useState([])
  const [fixedRows, setFixedRows] = useState([])
  const [done, setDone] = useState(false)
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    setVulnRows([])
    setFixedRows([])
    setDone(false)

    // --- VULNERABLE: 12 parolayı sırayla dene, canlı güncelle, doğru parolada dur ---
    const v = []
    for (let i = 0; i < PASSWORDS.length; i++) {
      const r = await proxy('vulnerable', MODULE07, SENARYO, 'login', {
        method: 'POST',
        body: { username, password: PASSWORDS[i] },
      })
      v.push({ i: i + 1, password: PASSWORDS[i], status: r.status })
      setVulnRows([...v])
      if (r.status === 200) break
    }

    // --- FIXED: aynı liste; kilitlenince kalanlar da 429 ---
    await proxy('fixed', MODULE07, SENARYO, 'reset', { method: 'POST' })
    const f = []
    for (let i = 0; i < PASSWORDS.length; i++) {
      const r = await proxy('fixed', MODULE07, SENARYO, 'login', {
        method: 'POST',
        body: { username, password: PASSWORDS[i] },
      })
      f.push({ i: i + 1, password: PASSWORDS[i], status: r.status })
      setFixedRows([...f])
    }
    setDone(true)
    setBusy(false)
  }

  const vulnHit = vulnRows.find((r) => r.status === 200)
  const fixedLocked = fixedRows.find((r) => r.status === 429)
  const fixedHit = fixedRows.find((r) => r.status === 200)

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 1 — Credential Stuffing (Brute-Force Koruması Yok)</h2>
        <div className="meta">CVSS 8.1 (High) · CWE-307 · A07:2025</div>
        <p>
          Hashing doğrudur (argon2id) — kusur parolanın <i>kaç kez</i> denenebildiğindedir. Deneme limiti
          olmadığından <code>carol</code>'un yaygın parolası (<code>Password1</code>, listede 12. sırada)
          engelsiz bulunur. Fix, 5 başarısız denemeden sonra hesabı kilitler.
        </p>
      </header>

      <div className="actionbar">
        <div className="field">
          <label>Kullanıcı adı (hedef)</label>
          <input value={username} onChange={(e) => setUsername(e.target.value)} style={{ minWidth: 160 }} />
        </div>
        <button className="btn primary" onClick={run} disabled={busy}>
          {busy ? 'Deneniyor…' : '12 Parola ile Dene (iki sürüme)'}
        </button>
      </div>

      {vulnHit && (
        <div className="banner leak">
          🔓 Parola bulundu: <code>{vulnHit.password}</code> ({vulnHit.i}. denemede) — hiç engellenmedi, tüm istekler aynı hızda işlendi.
        </div>
      )}
      {done && fixedLocked && !fixedHit && (
        <div className="banner safe">
          🔒 {fixedLocked.i}. denemede kilitlendi (429) — doğru parola (12. sırada) hiç sıraya giremedi.
        </div>
      )}

      <div className="compare">
        <AttemptTable title="Vulnerable — sınırsız deneme" rows={vulnRows} cls={vulnHit ? 'panel allowed' : 'panel'} />
        <AttemptTable title="Fixed — 5 deneme sonra kilitleme" rows={fixedRows} cls={fixedLocked ? 'panel blocked' : 'panel'} />
      </div>

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
