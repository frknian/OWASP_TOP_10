import { useState, useEffect, useRef } from 'react'
import { proxy, MODULE07 } from '../../api.js'
import { HowItWorks } from '../../ui.jsx'

const SENARYO = '03-session-timeout-logout-failure'
const TTL = 8 // fixed sürümün SESSION_TTL_SECONDS değeri

const STEPS = [
  'İki bağımsız kusur, aynı kökten: session yaşam döngüsünün sunucu tarafında yönetilmemesi.',
  'Vulnerable (a): SESSIONS sözlüğü created_at tutmaz → idle timeout yok, token süresiz geçerli.',
  'Vulnerable (b): /logout endpoint\'i VAR ama session\'ı silmez — sadece "başarılı" görünümü verir (placebo).',
  'Fixed (a): her session\'a created_at eklenir; /profile her istekte now - created_at > TTL kontrolü yapar, aşılırsa siler ve 401 döner.',
  'Fixed (b): /logout artık SESSIONS.pop() ile token\'ı GERÇEKTEN siler; sonraki istek 401 alır.',
]

const VULN_CODE = `SESSIONS: dict[str, str] = {}   # token -> username; created_at YOK, expiry YOK

@app.get("/profile")
def profile(session_token: str):
    username = SESSIONS.get(session_token)   # varlık kontrolü var, SÜRE kontrolü YOK
    ...

@app.post("/logout")
def logout(req: TokenRequest):
    # ZAFIYET: session SİLİNMİYOR — sadece "başarılı" mesajı
    return {"logged_out": True, ...}`

const FIXED_CODE = `SESSION_TTL_SECONDS = 8   # üretimde dakikalar/saatler

def _get_valid_session(token):
    entry = SESSIONS.get(token)
    if not entry: return None
    if time.time() - entry["created_at"] > SESSION_TTL_SECONDS:
        del SESSIONS[token]           # FIX (a): süresi dolan session GERÇEKTEN silinir
        return None
    return entry["username"]

@app.post("/logout")
def logout(req: TokenRequest):
    existed = SESSIONS.pop(req.session_token, None) is not None   # FIX (b): GERÇEKTEN siler
    return {"logged_out": True, "session_existed": existed, ...}`

function Panel({ variant, state }) {
  const isVuln = variant === 'vulnerable'
  const { token, elapsed, profile, loggedOut, autoChecked } = state
  const expiredFixed = !isVuln && profile?.status === 401
  const cls = !token ? 'panel' : expiredFixed ? 'panel blocked' : profile?.status === 200 ? 'panel allowed' : 'panel'

  return (
    <div className={cls}>
      <h3>{isVuln ? 'Vulnerable — timeout/logout yok' : `Fixed — ${TTL}sn TTL + gerçek logout`}</h3>
      {!token ? (
        <div className="muted">Henüz giriş yapılmadı.</div>
      ) : (
        <>
          <div className="statusline">
            Geçen süre:{' '}
            <b style={{ color: elapsed >= TTL && !isVuln ? '#ff9aa0' : '#7CFFB2', fontSize: 16 }}>{elapsed}s</b>
            {!isVuln && <> / {TTL}s TTL</>}
          </div>
          {profile && (
            <div className="statusline">
              GET /profile → <b style={{ color: profile.status === 200 ? '#7CFFB2' : '#ff9aa0' }}>HTTP {profile.status}</b>
              {autoChecked && <span className="muted"> (8sn'de otomatik kontrol)</span>}
            </div>
          )}
          {profile && <pre>{typeof profile.data === 'string' ? profile.data : JSON.stringify(profile.data, null, 2)}</pre>}

          {/* idle timeout banner'ları */}
          {autoChecked && isVuln && profile?.status === 200 && (
            <div className="banner leak">🔓 Zaman aşımı yok — session {elapsed}sn sonra hâlâ geçerli (sonsuza kadar).</div>
          )}
          {autoChecked && !isVuln && profile?.status === 401 && (
            <div className="banner safe">🔒 Idle timeout — {TTL}sn sonra session sunucu tarafında geçersiz kılındı.</div>
          )}

          {/* logout banner'ları */}
          {loggedOut && isVuln && profile?.status === 200 && (
            <div className="banner leak">🔓 Placebo logout — çıkış "başarılı" göründü ama token hâlâ 200 veriyor.</div>
          )}
          {loggedOut && !isVuln && profile?.status === 401 && (
            <div className="banner safe">🔒 Gerçek logout — token silindi, çıkış sonrası /profile 401.</div>
          )}
        </>
      )}
    </div>
  )
}

const EMPTY = { token: null, elapsed: 0, profile: null, loggedOut: false, autoChecked: false }

export default function SessionTimeoutDemo() {
  const [vuln, setVuln] = useState(EMPTY)
  const [fixed, setFixed] = useState(EMPTY)
  const [busy, setBusy] = useState(false)
  const loginAtRef = useRef(null)
  const autoFiredRef = useRef(false)

  // Canlı sayaç: login'den itibaren geçen süre; 8sn'de otomatik /profile kontrolü.
  useEffect(() => {
    if (!loginAtRef.current) return
    const id = setInterval(() => {
      const elapsed = Math.floor((Date.now() - loginAtRef.current) / 1000)
      setVuln((s) => (s.token ? { ...s, elapsed } : s))
      setFixed((s) => (s.token ? { ...s, elapsed } : s))
      if (elapsed >= TTL && !autoFiredRef.current) {
        autoFiredRef.current = true
        autoCheck()
      }
    }, 250)
    return () => clearInterval(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vuln.token, fixed.token])

  async function checkProfile(variant, token) {
    return proxy(variant, MODULE07, SENARYO, `profile?session_token=${encodeURIComponent(token)}`)
  }

  async function autoCheck() {
    setVuln((s) => s) // no-op guard
    const vTok = vuln.token
    const fTok = fixed.token
    if (vTok) {
      const p = await checkProfile('vulnerable', vTok)
      setVuln((s) => ({ ...s, profile: p, autoChecked: true }))
    }
    if (fTok) {
      const p = await checkProfile('fixed', fTok)
      setFixed((s) => ({ ...s, profile: p, autoChecked: true }))
    }
  }

  async function login() {
    setBusy(true)
    autoFiredRef.current = false
    const body = { username: 'alice', password: 'Tr@ck3r-Alice-99!' }
    const vl = await proxy('vulnerable', MODULE07, SENARYO, 'login', { method: 'POST', body })
    const fl = await proxy('fixed', MODULE07, SENARYO, 'login', { method: 'POST', body })
    const vTok = vl.data?.session_token
    const fTok = fl.data?.session_token
    // login sonrası anlık /profile (200 beklenir)
    const vp = vTok ? await checkProfile('vulnerable', vTok) : null
    const fp = fTok ? await checkProfile('fixed', fTok) : null
    loginAtRef.current = Date.now()
    setVuln({ token: vTok, elapsed: 0, profile: vp, loggedOut: false, autoChecked: false })
    setFixed({ token: fTok, elapsed: 0, profile: fp, loggedOut: false, autoChecked: false })
    setBusy(false)
  }

  async function manualCheck() {
    if (vuln.token) {
      const p = await checkProfile('vulnerable', vuln.token)
      setVuln((s) => ({ ...s, profile: p }))
    }
    if (fixed.token) {
      const p = await checkProfile('fixed', fixed.token)
      setFixed((s) => ({ ...s, profile: p }))
    }
  }

  async function logout() {
    setBusy(true)
    autoFiredRef.current = true // logout testinde otomatik timeout kontrolünü durdur
    if (vuln.token) {
      await proxy('vulnerable', MODULE07, SENARYO, 'logout', { method: 'POST', body: { session_token: vuln.token } })
      const p = await checkProfile('vulnerable', vuln.token)
      setVuln((s) => ({ ...s, profile: p, loggedOut: true, autoChecked: false }))
    }
    if (fixed.token) {
      await proxy('fixed', MODULE07, SENARYO, 'logout', { method: 'POST', body: { session_token: fixed.token } })
      const p = await checkProfile('fixed', fixed.token)
      setFixed((s) => ({ ...s, profile: p, loggedOut: true, autoChecked: false }))
    }
    setBusy(false)
  }

  const loggedIn = !!(vuln.token || fixed.token)

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 3 — Session Timeout / Logout Kırıklığı</h2>
        <div className="meta">CVSS 7.5 (High) · CWE-613 / CWE-287 · A07:2025</div>
        <p>
          Vulnerable'da session'ın idle timeout'u yoktur (süresiz geçerli) ve <code>/logout</code> endpoint'i
          session'ı gerçekten silmez (placebo). Fixed'de {TTL}sn TTL ve gerçek logout uygulanır. Aşağıdaki
          sayaç {TTL}sn'ye ulaşınca <code>/profile</code> otomatik yeniden kontrol edilir.
        </p>
      </header>

      <div className="actionbar">
        <button className="btn primary" onClick={login} disabled={busy}>
          Giriş Yap (iki sürüme)
        </button>
        <button className="btn" onClick={manualCheck} disabled={busy || !loggedIn}>
          /profile Kontrol Et
        </button>
        <button className="btn" onClick={logout} disabled={busy || !loggedIn}>
          Çıkış Yap (logout testi)
        </button>
      </div>

      <div className="compare">
        <Panel variant="vulnerable" state={vuln} />
        <Panel variant="fixed" state={fixed} />
      </div>

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
