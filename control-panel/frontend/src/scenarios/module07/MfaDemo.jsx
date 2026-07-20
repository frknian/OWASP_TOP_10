import { useState } from 'react'
import { proxy, MODULE07 } from '../../api.js'
import { HowItWorks } from '../../ui.jsx'

const SENARYO = '02-password-only-no-mfa'

const STEPS = [
  'Vulnerable akış TEK ADIM: parola doğru → doğrudan tam session. "Bildiğin bir şey" dışında faktör yok.',
  'Parola herhangi bir yolla (phishing, breach, credential stuffing) ele geçerse doğrudan hesap devralma olur.',
  'Fixed akış İKİ ADIM: parola doğru → yalnızca pending_token + OTP üretimi (tam session HENÜZ verilmez).',
  'OTP out-of-band gelir (gerçekte SMS/e-posta/authenticator; bu labda backend üretir). /login yanıtı OTP\'yi DÖNDÜRMEZ.',
  'Yalnızca doğru OTP ile POST /login/verify-mfa tam session verir. Parola doğru ama OTP\'siz erişim YOKTUR.',
]

const VULN_CODE = `@app.post("/login")
def login(req: LoginRequest):
    password_hasher.verify(...)                  # parola doğruysa...
    token = secrets.token_urlsafe(24)
    SESSIONS[token] = req.username
    return {"authenticated": True, "session_token": token}   # ...DOĞRUDAN tam erişim`

const FIXED_CODE = `@app.post("/login")                              # 1. ADIM
def login(req: LoginRequest):
    password_hasher.verify(...)                  # parola doğru → TAM session DEĞİL
    pending_token = secrets.token_urlsafe(24)
    otp_code = f"{random.randint(0, 999999):06d}"
    PENDING_MFA[pending_token] = {...}
    print(f"[MFA SİMÜLASYONU] OTP: {otp_code}")   # out-of-band; yanıtta DÖNMEZ
    return {"mfa_required": True, "pending_token": pending_token}

@app.post("/login/verify-mfa")                   # 2. ADIM
def verify_mfa(req):
    if req.otp_code != entry["otp_code"]:
        raise HTTPException(401, "Geçersiz OTP kodu")
    SESSIONS[session_token] = entry["username"]   # TAM session ANCAK şimdi`

function ResultBlock({ label, result }) {
  if (!result) return null
  const s = result.status
  const color = s >= 200 && s < 300 ? '#7CFFB2' : '#ff9aa0'
  return (
    <div style={{ marginTop: 8 }}>
      <div className="statusline">{label} → <b style={{ color }}>HTTP {s}</b></div>
      <pre>{typeof result.data === 'string' ? result.data : JSON.stringify(result.data, null, 2)}</pre>
    </div>
  )
}

export default function MfaDemo() {
  const [username, setUsername] = useState('alice')
  const [password, setPassword] = useState('Tr@ck3r-Alice-99!')
  const [busy, setBusy] = useState(false)

  // vulnerable
  const [vLogin, setVLogin] = useState(null)
  const [vProfile, setVProfile] = useState(null)
  // fixed
  const [fLogin, setFLogin] = useState(null)
  const [pending, setPending] = useState(null)
  const [labOtp, setLabOtp] = useState(null)
  const [otpInput, setOtpInput] = useState('')
  const [fVerify, setFVerify] = useState(null)
  const [fProfile, setFProfile] = useState(null)

  async function login() {
    setBusy(true)
    setVProfile(null); setFVerify(null); setFProfile(null); setPending(null); setLabOtp(null); setOtpInput('')

    // --- VULNERABLE: parola → doğrudan tam session → /profile ---
    const vl = await proxy('vulnerable', MODULE07, SENARYO, 'login', { method: 'POST', body: { username, password } })
    setVLogin(vl)
    if (vl.status === 200 && vl.data?.session_token) {
      const vp = await proxy('vulnerable', MODULE07, SENARYO, `profile?session_token=${encodeURIComponent(vl.data.session_token)}`)
      setVProfile(vp)
    }

    // --- FIXED: parola → sadece pending_token (+ lab OTP gelen kutusu) ---
    const fl = await proxy('fixed', MODULE07, SENARYO, 'login', { method: 'POST', body: { username, password } })
    setFLogin(fl)
    if (fl.status === 200 && fl.data?.pending_token) {
      setPending(fl.data.pending_token)
      // Lab-only: OTP normalde SMS/e-posta ile gelir; panelden okunabilmesi için gelen kutusu endpoint'i.
      const inbox = await proxy('fixed', MODULE07, SENARYO, `lab/otp-inbox?pending_token=${encodeURIComponent(fl.data.pending_token)}`)
      if (inbox.status === 200) setLabOtp(inbox.data?.otp_code)
    }
    setBusy(false)
  }

  async function verifyMfa() {
    setBusy(true)
    const r = await proxy('fixed', MODULE07, SENARYO, 'login/verify-mfa', {
      method: 'POST',
      body: { pending_token: pending, otp_code: otpInput },
    })
    setFVerify(r)
    if (r.status === 200 && r.data?.session_token) {
      const p = await proxy('fixed', MODULE07, SENARYO, `profile?session_token=${encodeURIComponent(r.data.session_token)}`)
      setFProfile(p)
    } else {
      setFProfile(null)
    }
    setBusy(false)
  }

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 2 — Tek Faktör Olarak Parola (MFA Yokluğu)</h2>
        <div className="meta">CVSS 8.1 (High) · CWE-308 · A07:2025</div>
        <p>
          Vulnerable akışta doğru parola <b>doğrudan</b> tam erişim verir. Fixed akış iki adımlıdır: parola
          doğru olsa da OTP girilmeden hiçbir korumalı kaynağa erişilemez. NIST 800-63B: asıl savunma parola
          karmaşıklığı değil, MFA'dır.
        </p>
      </header>

      <div className="actionbar">
        <div className="field">
          <label>Kullanıcı adı</label>
          <input value={username} onChange={(e) => setUsername(e.target.value)} style={{ minWidth: 130 }} />
        </div>
        <div className="field">
          <label>Parola</label>
          <input value={password} onChange={(e) => setPassword(e.target.value)} style={{ minWidth: 180 }} />
        </div>
        <button className="btn primary" onClick={login} disabled={busy}>
          Giriş Yap (iki sürüme)
        </button>
      </div>

      <div className="compare">
        {/* VULNERABLE */}
        <div className={vProfile?.status === 200 ? 'panel allowed' : 'panel'}>
          <h3>Vulnerable — tek faktör</h3>
          {!vLogin ? (
            <div className="muted">Henüz giriş yapılmadı.</div>
          ) : (
            <>
              {vProfile?.status === 200 && (
                <div className="banner leak">🔓 Tam erişim verildi (tek faktör) — parola tek başına /profile'ı açtı.</div>
              )}
              <ResultBlock label="POST /login" result={vLogin} />
              <ResultBlock label="GET /profile" result={vProfile} />
            </>
          )}
        </div>

        {/* FIXED */}
        <div className={fProfile?.status === 200 ? 'panel allowed' : 'panel blocked'}>
          <h3>Fixed — parola + MFA</h3>
          {!fLogin ? (
            <div className="muted">Henüz giriş yapılmadı.</div>
          ) : (
            <>
              {pending && !fProfile && (
                <div className="banner safe">🔒 MFA gerekli — parola doğru ama tam session verilmedi. OTP bekleniyor.</div>
              )}
              <ResultBlock label="POST /login" result={fLogin} />

              {pending && (
                <div className="note" style={{ marginTop: 8 }}>
                  ℹ️ Gerçek ortamda bu OTP <b>SMS/e-posta ile</b> gelirdi. Bu labda backend üretir ve panelin okuyabilmesi
                  için lab-only bir gelen kutusu endpoint'inden gösterilir. <code>/login</code> yanıtı OTP'yi <b>döndürmez</b>.
                  {labOtp && <> — Gelen kutusundaki kod: <b style={{ fontFamily: 'monospace', color: '#7CFFB2' }}>{labOtp}</b></>}
                </div>
              )}

              {pending && !fProfile && (
                <div className="actionbar" style={{ marginTop: 8 }}>
                  <div className="field">
                    <label>OTP kodu</label>
                    <input value={otpInput} onChange={(e) => setOtpInput(e.target.value)} placeholder="6 hane" style={{ minWidth: 110 }} />
                  </div>
                  {labOtp && (
                    <button className="btn" onClick={() => setOtpInput(labOtp)} disabled={busy}>
                      Gelen kutusundaki kodu doldur
                    </button>
                  )}
                  <button className="btn primary" onClick={verifyMfa} disabled={busy || !otpInput}>
                    OTP Doğrula
                  </button>
                </div>
              )}

              <ResultBlock label="POST /login/verify-mfa" result={fVerify} />
              {fProfile?.status === 200 && (
                <div className="banner safe">🔒 İki faktör tamamlandı — MFA sonrası tam session ile /profile açıldı.</div>
              )}
              <ResultBlock label="GET /profile" result={fProfile} />
            </>
          )}
        </div>
      </div>

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
