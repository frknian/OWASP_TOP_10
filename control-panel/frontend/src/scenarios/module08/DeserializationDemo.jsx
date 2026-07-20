import { useState } from 'react'
import { proxy, MODULE08 } from '../../api.js'
import { SimBanner, HowItWorks } from '../../ui.jsx'

const SENARYO = '01-insecure-deserialization-defanged'
// Tehlikeli pickle-benzeri payload: __reduce__ + os.system pattern'i içerir (base64).
const DANGEROUS_PAYLOAD = btoa("cos\nsystem\n(S'cat /etc/passwd'\ntR.__reduce__")

const STEPS = [
  'Sunucu, client\'a emanet ettiği state\'i geri aldığında (a) gerçekten kendisinden mi geldiğini ve (b) değişmediğini doğrulamalıdır.',
  'pickle özellikle tehlikelidir: sadece "veri" değil, deserialize sırasında KOD çalıştırabilen (__reduce__) bir formattır.',
  'Vulnerable: hiçbir imza/doğrulama yok. __reduce__ payload\'ı gerçek pickle.loads ile RCE olurdu (burada DEFANGED — sadece simüle edilir).',
  'Fixed KONTROL 1 — HMAC imzası: "veri sunucudan mı geldi / değişti mi?" (server-side secret ile constant-time doğrulama).',
  'Fixed KONTROL 2 — JSON + katı şema: "format/yapı doğru mu?" (pickle yok, extra="forbid" + değer allowlist). İkisi birlikte gerekli: HMAC yapıyı, şema kaynağı kontrol edemez.',
]

const VULN_CODE = `@app.post("/restore-state")
def restore_state(req: RestoreRequest):   # {state}
    decoded = base64.b64decode(req.state).decode(...)
    # Gerçek sistemde: obj = pickle.loads(...)  ← RCE noktası (DEFANGED)
    # Hiçbir imza/bütünlük kontrolü yok — veri olduğu gibi kabul.`

const FIXED_CODE = `@app.post("/restore-state")
def restore_state(req: RestoreRequest):   # {state, signature}
    # KONTROL 1 — HMAC: veri sunucudan mı geldi / değişti mi?
    expected = hmac.new(SECRET, req.state.encode(), sha256).hexdigest()
    if not hmac.compare_digest(req.signature, expected):
        raise HTTPException(400, "[GÜVENLİ] İmza doğrulanamadı...")
    # KONTROL 2 — JSON + katı şema (pickle YOK)
    validated = StateSchema(**json.loads(req.state))   # extra="forbid"`

function Panel({ title, cls, children }) {
  return (
    <div className={cls}>
      <h3>{title}</h3>
      {children}
    </div>
  )
}

export default function DeserializationDemo() {
  const [vGet, setVGet] = useState(null)
  const [fGet, setFGet] = useState(null)
  const [vRestore, setVRestore] = useState(null)
  const [fRestore, setFRestore] = useState(null)
  const [fTamper, setFTamper] = useState(null)
  const [busy, setBusy] = useState(false)

  async function getState() {
    setBusy(true)
    setVRestore(null); setFRestore(null); setFTamper(null)
    setVGet(await proxy('vulnerable', MODULE08, SENARYO, 'get-state'))
    setFGet(await proxy('fixed', MODULE08, SENARYO, 'get-state'))
    setBusy(false)
  }

  async function sendDangerous() {
    setBusy(true)
    // Vulnerable: {state} — tehlikeli payload → [SİMÜLASYON]
    setVRestore(await proxy('vulnerable', MODULE08, SENARYO, 'restore-state', {
      method: 'POST', body: { state: DANGEROUS_PAYLOAD },
    }))
    // Fixed: {state, signature} — imzasız pickle payload → 400 [GÜVENLİ]
    setFRestore(await proxy('fixed', MODULE08, SENARYO, 'restore-state', {
      method: 'POST', body: { state: DANGEROUS_PAYLOAD, signature: '' },
    }))
    setBusy(false)
  }

  async function tamperSignature() {
    if (!fGet?.data?.state) {
      // önce state alınmalı
      const g = await proxy('fixed', MODULE08, SENARYO, 'get-state')
      setFGet(g)
      if (!g.data?.state) return
    }
    setBusy(true)
    const g = fGet?.data?.state ? fGet : await proxy('fixed', MODULE08, SENARYO, 'get-state')
    // state'i değiştir (dark → hacked), imzayı olduğu gibi bırak → HMAC uyuşmaz
    const tamperedState = String(g.data.state).replace('dark', 'hacked')
    setFTamper(await proxy('fixed', MODULE08, SENARYO, 'restore-state', {
      method: 'POST', body: { state: tamperedState, signature: g.data.signature },
    }))
    setBusy(false)
  }

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 1 — Insecure Deserialization</h2>
        <div className="meta">CVSS 9.8 (Critical, defanged) · CWE-502 · A08:2025</div>
        <p>
          Sunucu, client'a emanet ettiği state'i imza/bütünlük kontrolü olmadan geri yükler. Gerçek bir
          pickle implementasyonunda bu, <code>__reduce__</code> payload'ı ile RCE'ye dönüşür. Fixed sürüm
          <b> HMAC imza + JSON şema</b> ikilisini birlikte uygular.
        </p>
        <div className="note">
          ⚠️ DEFANGED: Gerçek <code>pickle.loads()</code> hiçbir sürümde çalıştırılmaz. Vulnerable yalnızca
          tehlikeli pattern'i tespit edip "çalışsaydı ne olurdu" simüle eder.
        </div>
      </header>

      <div className="actionbar">
        <button className="btn primary" onClick={getState} disabled={busy}>
          Durumu Al (iki sürüme)
        </button>
        <button className="btn" onClick={sendDangerous} disabled={busy}>
          Zararlı Payload ile Geri Gönder
        </button>
        <button className="btn" onClick={tamperSignature} disabled={busy}>
          İmzayı Boz ve Gönder (fixed)
        </button>
      </div>

      <div className="compare">
        {/* VULNERABLE */}
        <Panel title="Vulnerable — imza/doğrulama yok" cls={vRestore ? 'panel allowed' : 'panel'}>
          {!vGet ? (
            <div className="muted">Henüz istek atılmadı.</div>
          ) : (
            <>
              <div className="statusline">GET /get-state (imzasız):</div>
              <pre>{JSON.stringify(vGet.data, null, 2)}</pre>
              {vRestore && (
                <>
                  <div className="statusline" style={{ marginTop: 8 }}>POST /restore-state (zararlı payload) → HTTP {vRestore.status}:</div>
                  <SimBanner response={vRestore} />
                  <pre>{JSON.stringify(vRestore.data, null, 2)}</pre>
                </>
              )}
            </>
          )}
        </Panel>

        {/* FIXED */}
        <Panel title="Fixed — HMAC imza + JSON şema" cls={(fRestore || fTamper) ? 'panel blocked' : 'panel'}>
          {!fGet ? (
            <div className="muted">Henüz istek atılmadı.</div>
          ) : (
            <>
              <div className="statusline">GET /get-state (state + signature):</div>
              <pre>{JSON.stringify(fGet.data, null, 2)}</pre>
              {fRestore && (
                <>
                  <div className="statusline" style={{ marginTop: 8 }}>POST /restore-state (imzasız pickle) → HTTP {fRestore.status}:</div>
                  <SimBanner response={fRestore} />
                  <pre>{JSON.stringify(fRestore.data, null, 2)}</pre>
                </>
              )}
              {fTamper && (
                <>
                  <div className="statusline" style={{ marginTop: 8 }}>POST /restore-state (state değiştirildi, eski imza) → HTTP {fTamper.status}:</div>
                  <SimBanner response={fTamper} />
                  <pre>{JSON.stringify(fTamper.data, null, 2)}</pre>
                </>
              )}
            </>
          )}
        </Panel>
      </div>

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
