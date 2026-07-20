import { useState } from 'react'
import { proxy, MODULE06 } from '../../api.js'
import { HowItWorks } from '../../ui.jsx'

const SENARYO = '01-insecure-credential-recovery-questions'
// Türkiye'nin en yaygın soyadları/şehirleri — seed cevaplar bunlardan seçildi (bob → "istanbul").
const GUESSES = ['yilmaz', 'kaya', 'demir', 'istanbul', 'ankara']
const NEW_PASSWORD = 'attacker-owns-this'

const STEPS = [
  'Güvenlik sorusu bir kimlik KANITI değildir: cevabı aile, arkadaşlar, OSINT ile bilinebilir/tahmin edilebilir.',
  'Vulnerable akış /security-question ile soruyu kimlik doğrulamasız sızdırır (+ hesabın varlığını doğrular).',
  'Seed cevaplar yaygın soyad/şehirlerden seçilmiştir; deneme sınırı olmadığından kalan belirsizlik brute-force ile erir.',
  'Cevap tutunca reset_token doğrudan yanıtta döner → saldırgan parolayı değiştirip hesabı devralır.',
  'Fix bir kod yaması DEĞİL, TASARIM değişikliğidir: güvenlik sorusu mekanizması TAMAMEN kaldırıldı (endpoint 410, eski API alanı 422); yerine username-only + out-of-band, süreli, tek kullanımlık token akışı geldi.',
]

const VULN_CODE = `@app.post("/recover-password")
def recover_password(req: RecoverRequest):   # {username, security_answer}
    if req.security_answer.strip().lower() != user["answer"]:
        raise HTTPException(403, "Güvenlik sorusu cevabı hatalı")   # deneme sınırı YOK
    token = secrets.token_urlsafe(16)
    RESET_TOKENS[token] = req.username
    return {"allowed": True, "reset_token": token, ...}   # token doğrudan yanıtta`

const FIXED_CODE = `class RecoverRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")   # security_answer → 422
    username: str                               # SADECE username

@app.get("/security-question")
def security_question_removed(username: str = ""):
    raise HTTPException(410, "Bu endpoint kaldırıldı...")   # mekanizma silindi

@app.post("/recover-password")
def recover_password(req: RecoverRequest):
    # token yanıtta DÖNMEZ — out-of-band (e-posta) gönderilir; kullanıcı yok/var → aynı yanıt
    return {"message": "...e-posta adresine gönderildi (simülasyon)", ...}`

function statusColor(s) {
  if (s >= 200 && s < 300) return '#7CFFB2'
  if (s === 403 || s === 401) return '#ff9aa0'
  return '#d3d9e6'
}

export default function CredentialRecoveryDemo() {
  const [username, setUsername] = useState('bob')
  const [guess, setGuess] = useState('')
  const [question, setQuestion] = useState(null) // {vuln, fixed}
  const [steps, setSteps] = useState([]) // brute-force adımları
  const [found, setFound] = useState(null)
  const [takeover, setTakeover] = useState(null)
  const [fixed, setFixed] = useState(null) // {oldApi, endpoint, newFlow}
  const [busy, setBusy] = useState(false)

  async function leakQuestion() {
    setBusy(true)
    const vuln = await proxy('vulnerable', MODULE06, SENARYO, `security-question?username=${encodeURIComponent(username)}`)
    const fx = await proxy('fixed', MODULE06, SENARYO, `security-question?username=${encodeURIComponent(username)}`)
    setQuestion({ vuln, fixed: fx })
    setBusy(false)
  }

  async function singleGuess() {
    if (!guess) return
    setBusy(true)
    setFixed(null)
    setTakeover(null)
    const r = await proxy('vulnerable', MODULE06, SENARYO, 'recover-password', {
      method: 'POST',
      body: { username, security_answer: guess },
    })
    setSteps([{ answer: guess, status: r.status, ok: r.ok }])
    if (r.ok && r.data?.reset_token) {
      setFound({ answer: guess, token: r.data.reset_token })
      const t = await proxy('vulnerable', MODULE06, SENARYO, 'reset-password', {
        method: 'POST',
        body: { username, reset_token: r.data.reset_token, new_password: NEW_PASSWORD },
      })
      setTakeover(t)
    } else {
      setFound(null)
    }
    setBusy(false)
  }

  async function bruteForce() {
    setBusy(true)
    setSteps([])
    setFound(null)
    setTakeover(null)
    setFixed(null)

    // 1) VULNERABLE: 5 yaygın cevabı sırayla dene
    const collected = []
    let hit = null
    for (const answer of GUESSES) {
      const r = await proxy('vulnerable', MODULE06, SENARYO, 'recover-password', {
        method: 'POST',
        body: { username, security_answer: answer },
      })
      collected.push({ answer, status: r.status, ok: r.ok })
      setSteps([...collected])
      if (r.ok && r.data?.reset_token) {
        hit = { answer, token: r.data.reset_token }
        break
      }
    }
    setFound(hit)

    // 2) VULNERABLE: bulunan cevapla otomatik hesap devralma
    if (hit) {
      const t = await proxy('vulnerable', MODULE06, SENARYO, 'reset-password', {
        method: 'POST',
        body: { username, reset_token: hit.token, new_password: NEW_PASSWORD },
      })
      setTakeover(t)
    }

    // 3) FIXED: aynı akış artık çalışmıyor + yeni tasarımın gösterimi
    const oldApi = await proxy('fixed', MODULE06, SENARYO, 'recover-password', {
      method: 'POST',
      body: { username, security_answer: 'yilmaz' },
    })
    const endpoint = await proxy('fixed', MODULE06, SENARYO, `security-question?username=${encodeURIComponent(username)}`)
    const newFlow = await proxy('fixed', MODULE06, SENARYO, 'recover-password', {
      method: 'POST',
      body: { username },
    })
    setFixed({ oldApi, endpoint, newFlow })

    setBusy(false)
  }

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 1 — Insecure Credential Recovery (Güvenlik Soruları)</h2>
        <div className="meta">CVSS 8.1 (High) · CWE-640 · A06:2025</div>
        <p>
          Parola sıfırlama, kimlik kanıtı olarak "güvenlik sorusu" cevabına dayanır. Cevap paylaşılabilir,
          düşük entropili ve rotate edilemez olduğundan mekanizmanın kendisi kusurludur. Fix, soruyu
          iyileştirmek değil <b>tamamen kaldırmaktır</b>.
        </p>
      </header>

      <div className="actionbar">
        <div className="field">
          <label>Kullanıcı adı (hedef)</label>
          <input value={username} onChange={(e) => setUsername(e.target.value)} style={{ minWidth: 160 }} />
        </div>
        <div className="field">
          <label>Tahmin (tek cevap)</label>
          <input value={guess} onChange={(e) => setGuess(e.target.value)} placeholder="örn. istanbul" style={{ minWidth: 140 }} />
        </div>
        <button className="btn" onClick={leakQuestion} disabled={busy}>
          Güvenlik Sorusunu Sız
        </button>
        <button className="btn" onClick={singleGuess} disabled={busy || !guess}>
          Tek Tahmin Dene
        </button>
        <button className="btn primary" onClick={bruteForce} disabled={busy}>
          Brute-Force Dene (5 yaygın cevap)
        </button>
      </div>

      {/* Soru sızıntısı: vuln açığa vurur, fixed 410 */}
      {question && (
        <div className="compare">
          <div className={question.vuln.ok ? 'panel allowed' : 'panel'}>
            <h3>Vulnerable — /security-question <span className="badge">HTTP {question.vuln.status}</span></h3>
            <pre>{JSON.stringify(question.vuln.data, null, 2)}</pre>
            {question.vuln.ok && <div className="banner leak">🔓 Soru kimlik doğrulamasız sızdı — saldırgan neyi araştıracağını öğrendi.</div>}
          </div>
          <div className={question.fixed.status === 410 ? 'panel blocked' : 'panel'}>
            <h3>Fixed — /security-question <span className="badge">HTTP {question.fixed.status}</span></h3>
            <pre>{JSON.stringify(question.fixed.data, null, 2)}</pre>
            {question.fixed.status === 410 && <div className="banner safe">🔒 410 Gone — endpoint tasarımdan kaldırıldı.</div>}
          </div>
        </div>
      )}

      {/* Brute-force adımları */}
      {steps.length > 0 && (
        <div className="panel" style={{ marginTop: 12 }}>
          <h3>Vulnerable — Brute-Force Adımları (deneme sınırı yok)</h3>
          <ol className="steps">
            {steps.map((s, i) => (
              <li key={i}>
                <code>{s.answer}</code> →{' '}
                <b style={{ color: statusColor(s.status) }}>
                  {s.status} {s.ok ? '✅' : '❌'}
                </b>
              </li>
            ))}
          </ol>
          {found ? (
            <div className="banner leak">🔓 Cevap bulundu: <code>{found.answer}</code> ({GUESSES.indexOf(found.answer) + 1}. denemede) — hiçbir kilitleme/gecikme devreye girmedi.</div>
          ) : (
            <div className="banner neutral">Bu 5 yaygın cevap tutmadı — farklı bir hedef/cevap kümesi deneyin.</div>
          )}
        </div>
      )}

      {/* Hesap devralma */}
      {takeover && (
        <div className={takeover.ok ? 'panel allowed' : 'panel'} style={{ marginTop: 12 }}>
          <h3>Vulnerable — Hesabı Devral <span className="badge">HTTP {takeover.status}</span></h3>
          <pre>{JSON.stringify(takeover.data, null, 2)}</pre>
          {takeover.ok && (
            <div className="banner leak">
              🔓 Hesap devralındı — parola artık <code>{NEW_PASSWORD}</code>. Kurban kendi hesabından kilitlendi.
            </div>
          )}
        </div>
      )}

      {/* Fixed: tasarım kaldırıldı */}
      {fixed && (
        <div className="panel blocked" style={{ marginTop: 12 }}>
          <h3>Fixed — Aynı Saldırı Denendiğinde</h3>
          <div className="banner safe">🔒 Bu tasarım tamamen kaldırıldı — güvenlik sorusu yok.</div>
          <p className="muted" style={{ margin: '8px 0 4px' }}>
            Eski API (<code>security_answer</code> ile) → <b style={{ color: statusColor(fixed.oldApi.status) }}>HTTP {fixed.oldApi.status}</b> (extra_forbidden);{' '}
            <code>/security-question</code> → <b style={{ color: statusColor(fixed.endpoint.status) }}>HTTP {fixed.endpoint.status}</b> (Gone).
          </p>
          <h4 style={{ margin: '10px 0 4px' }}>Yerine gelen tasarım — username-only, out-of-band token:</h4>
          <div className="statusline">POST /recover-password {'{'}username{'}'} → HTTP {fixed.newFlow.status}</div>
          <pre>{JSON.stringify(fixed.newFlow.data, null, 2)}</pre>
          <div className="note">
            ℹ️ Token yanıt gövdesinde DÖNMEZ; gerçek sistemde e-postaya (bu labda sunucu konsoluna) gönderilir,
            15 dk geçerli ve tek kullanımlıktır. Kullanıcı var olsun/olmasın yanıt aynıdır (enumeration yok).
          </div>
        </div>
      )}

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
