import { useState, useEffect } from 'react'
import { startBackend, MODULE08 } from '../../api.js'
import { HowItWorks } from '../../ui.jsx'

const SENARYO = '03-missing-subresource-integrity'
// main.py'lerdeki # PORT: değerleri (start yanıtı gelmezse fallback).
const FALLBACK = { vulnerable: 8240, fixed: 8241 }

const STEPS = [
  'SRI (W3C standardı): <script> tag\'ine kaynağın beklenen içeriğinin kriptografik özeti (integrity="sha384-...") gömülür.',
  'Tarayıcı script\'i indirdikten sonra özetini hesaplar; gömülü değerle eşleşmezse script\'i ÇALIŞTIRMAZ.',
  'Vulnerable: <script>\'te integrity YOK → CDN ele geçirilirse tarayıcı değiştirilmiş kodu sorgusuz çalıştırır.',
  'Fixed: integrity hash HER ZAMAN meşru sürümündür; tampered içerik geldiğinde özet tutmaz ve tarayıcı reddeder.',
  'Hash hesabı: hashlib.sha384(lib.js).digest() → base64. Eşdeğeri: openssl dgst -sha384 -binary lib.js | openssl base64 -A',
]

const VULN_CODE = `<!-- vulnerable: integrity/crossorigin YOK -->
<script src="http://127.0.0.1:8240/cdn/lib.js"></script>`

const FIXED_CODE = `# hash import anında hesaplanır (byte-for-byte doğru):
digest = hashlib.sha384(LIB_JS_BENIGN.encode()).digest()
LIB_JS_SRI = "sha384-" + base64.b64encode(digest).decode()

<!-- fixed: SHA-384 integrity + crossorigin -->
<script src="http://127.0.0.1:8241/cdn/lib.js"
        integrity="sha384-..." crossorigin="anonymous"></script>`

function Frame({ label, port, tampered, setTampered, expectBlocked }) {
  const src = port
    ? `http://127.0.0.1:${port}/` + (tampered ? '?tampered=true' : '')
    : null
  return (
    <div className="panel">
      <h3>{label}</h3>
      <div className="actionbar" style={{ marginBottom: 8 }}>
        <button className={`btn ${!tampered ? 'primary' : ''}`} onClick={() => setTampered(false)}>
          Normal
        </button>
        <button className={`btn ${tampered ? 'primary' : ''}`} onClick={() => setTampered(true)}>
          Tampered (?tampered=true)
        </button>
      </div>
      {tampered && expectBlocked && (
        <div className="banner safe">🔒 Beklenen: script ÇALIŞMAZ (SRI engelledi) — durum "script bekleniyor…" kalır.</div>
      )}
      {tampered && !expectBlocked && (
        <div className="banner leak">🔓 Beklenen: değiştirilmiş script ÇALIŞIR — "⚠️ CDN ELE GEÇİRİLDİ" görünür.</div>
      )}
      {!port ? (
        <div className="muted">Backend başlatılıyor…</div>
      ) : (
        <iframe
          key={src}
          src={src}
          title={label}
          style={{ width: '100%', height: 180, border: '1px solid #333', background: '#fff', borderRadius: 6 }}
        />
      )}
      <div className="statusline" style={{ marginTop: 6 }}>
        iframe kaynağı: <code>{src || '(bekleniyor)'}</code>
      </div>
    </div>
  )
}

export default function SriDemo() {
  const [vPort, setVPort] = useState(null)
  const [fPort, setFPort] = useState(null)
  const [vTampered, setVTampered] = useState(false)
  const [fTampered, setFTampered] = useState(false)
  const [err, setErr] = useState(null)

  // Backend'leri otomatik başlat (idempotent). iframe DOĞRUDAN backend portundan yüklenecek
  // (proxy'den DEĞİL) — SRI'nin doğru çalışması için script gerçek origin'den gelmeli.
  useEffect(() => {
    let alive = true
    async function boot() {
      try {
        const v = await startBackend('vulnerable', MODULE08, SENARYO)
        const f = await startBackend('fixed', MODULE08, SENARYO)
        if (!alive) return
        setVPort(v.port || FALLBACK.vulnerable)
        setFPort(f.port || FALLBACK.fixed)
        if (v.error || f.error) setErr(v.error || f.error)
      } catch {
        if (alive) { setVPort(FALLBACK.vulnerable); setFPort(FALLBACK.fixed) }
      }
    }
    boot()
    return () => { alive = false }
  }, [])

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 3 — Missing Subresource Integrity (SRI)</h2>
        <div className="meta">CVSS 8.6 (High) · CWE-829 · A08:2025</div>
        <p>
          Sayfa bir "CDN"den (kendi <code>/cdn/lib.js</code> endpoint'imiz) script yükler. Vulnerable'da{' '}
          <code>&lt;script&gt;</code>'te <code>integrity</code> yoktur; fixed'de SHA-384 SRI hash'i vardır.
        </p>
        <div className="note">
          🔬 <b>Bu senaryo GERÇEK tarayıcı davranışı gösterir — defanged DEĞİL.</b> Aşağıdaki iframe'ler
          doğrudan backend portlarından (8240/8241) yüklenir; SRI kontrolünü tarayıcının kendisi yapar.
          <br />
          <b>Fixed + Tampered'da script'in ÇALIŞMAMASI beklenen davranıştır</b> — bu, tarayıcının SRI
          korumasının işe yaradığının kanıtıdır (durum "script bekleniyor…" olarak kalır).
        </div>
      </header>

      {err && <div className="banner neutral">Uyarı: {err} (venv kurulu değilse ilgili modülde setup_venvs.sh çalıştırın.)</div>}

      <div className="compare">
        <Frame label="Vulnerable — SRI YOK" port={vPort} tampered={vTampered} setTampered={setVTampered} expectBlocked={false} />
        <Frame label="Fixed — SRI VAR" port={fPort} tampered={fTampered} setTampered={setFTampered} expectBlocked={true} />
      </div>

      <div className="note" style={{ marginTop: 12 }}>
        💡 Karşılaştırma: her iki iframe'i de <b>Tampered</b>'a alın. Vulnerable'da kırmızı "⚠️ CDN ELE
        GEÇİRİLDİ" görünür (script çalıştı); Fixed'de "script bekleniyor…" kalır (tarayıcı SRI ile engelledi).
        Tarayıcı konsolunda fixed için bir SRI hatası da görürsünüz.
      </div>

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
