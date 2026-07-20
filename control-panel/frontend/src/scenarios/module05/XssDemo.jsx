import { useState } from 'react'
import { proxy, MODULE05 } from '../../api.js'
import { HowItWorks } from '../../ui.jsx'

const SENARYO = '04-reflected-xss'
const PAYLOAD = '<script>document.body.innerHTML = \'<h1 style="color:red">XSS ÇALIŞTI!</h1>\'</script>'

const STEPS = [
  'Endpoint bir HTML sayfası döndürüyor ve q parametresini HİÇ escape etmeden gövdeye gömüyor.',
  'Girdi HTML olarak yorumlandığından, <script> etiketi kurbanın tarayıcısında çalışır (reflected XSS).',
  'Zararsız PoC: <script>document.body.innerHTML=...</script> — sandbox içindeki izole sayfayı değiştirir (ana sayfaya erişmez).',
  'Gerçek saldırıda bu, çerez/oturum çalma veya kurban adına işlem için kullanılırdı.',
  'Fixed sürüm html.escape() ile çıktı kodlaması yapar: < > ve tek tırnak (&#x27;) dahil kodlanır, script çalışmaz.',
]

const VULN_CODE = `@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    # ZAFIYET: q escape edilmeden HTML'e gömülüyor → reflected XSS.
    return f"""<html>
  <body>
    <h1>Arama sonucu: {q}</h1>
    ...
  </body>
</html>"""`

const FIXED_CODE = `import html

@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    # FIX: Girdi HTML bağlamına uygun escape'ten geçer; <script> artık düz metin.
    safe_q = html.escape(q)
    return f"""<html>
  <body>
    <h1>Arama sonucu: {safe_q}</h1>
    ...
  </body>
</html>"""`

function XssPanel({ title, response }) {
  const [showSandbox, setShowSandbox] = useState(false)
  if (!response) {
    return (
      <div className="panel">
        <h3>{title}</h3>
        <div className="muted">Henüz istek atılmadı.</div>
      </div>
    )
  }
  // ÖNEMLİ: yanıt gövdesi HTML olsa da burada RENDER ETMİYORUZ — metin olarak gösteriyoruz
  // (React {} içeriğini otomatik escape eder), böylece panelin kendi origin'inde XSS oluşmaz.
  const source = typeof response.data === 'string' ? response.data : JSON.stringify(response.data, null, 2)
  const hasRawScript = source.includes('<script>')
  const cls = hasRawScript ? 'panel allowed' : 'panel blocked'
  const badge = hasRawScript ? '🔓 Ham <script> yansıdı' : '🔒 Escape edildi'
  return (
    <div className={cls}>
      <h3>
        {title} <span className="badge">{badge}</span>
      </h3>
      <div className="statusline">HTTP {response.status} · yanıt gövdesi (metin olarak):</div>
      <pre>{source}</pre>

      <button className="btn" onClick={() => setShowSandbox((s) => !s)} style={{ marginTop: 4 }}>
        {showSandbox ? '■ Sandbox\'ı Kapat' : '▶ Sandbox\'ta Çalıştır'}
      </button>
      {showSandbox && (
        <>
          {/* KRİTİK: sandbox="allow-scripts" TEK BAŞINA — allow-same-origin YOK. iframe opak
              origin'de izole çalışır; panelin DOM'una/cookie'sine/üst pencereye erişemez. */}
          <iframe
            sandbox="allow-scripts"
            srcDoc={source}
            style={{ width: '100%', height: '150px', border: '1px solid #333', background: '#fff', marginTop: '8px' }}
            title="XSS Sandbox Preview"
          />
          <div className="muted" style={{ fontSize: 12, marginTop: 6 }}>
            {hasRawScript
              ? 'Bu iframe izole bir sandbox\'ta çalışıyor (allow-scripts, same-origin YOK); ana sayfanıza hiçbir erişimi yok.'
              : 'Escape edilmiş yanıt: tarayıcı <script>\'i düz metin olarak render eder, kod çalışmaz.'}
          </div>
        </>
      )}
    </div>
  )
}

export default function XssDemo() {
  const [q, setQ] = useState('merhaba')
  const [results, setResults] = useState({})
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      next[v] = await proxy(v, MODULE05, SENARYO, `search?q=${encodeURIComponent(q)}`)
    }
    setResults(next)
    setBusy(false)
  }

  const vulnRaw = results.vulnerable?.data && String(results.vulnerable.data).includes('<script>')

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 4 — Reflected XSS</h2>
        <div className="meta">CVSS 6.1 (Medium) · CWE-79 · A05:2025</div>
        <p>
          <code>q</code> parametresi HTML'e escape edilmeden yansıtılıyor; <code>&lt;script&gt;</code> etiketi
          tarayıcıda çalışır. Fixed sürüm <code>html.escape()</code> ile kodlar. Aşağıda yanıt gövdesi{' '}
          <b>metin olarak</b> gösterilir (panelde render edilmez).
        </p>
        <div className="note">
          ℹ️ Script'in gerçekten çalıştığını görmek için vulnerable uygulamayı kendi portunda tarayıcıda açın:
          <code> http://127.0.0.1:8150/search?q=&lt;script&gt;...&lt;/script&gt;</code> — sekme başlığı "XSS-Demo" olur.
          Panel, güvenlik için yanıtı yalnızca metin gösterir.
        </div>
      </header>

      <div className="actionbar">
        <div className="field" style={{ flex: 1, minWidth: 280 }}>
          <label>Arama sorgusu (q)</label>
          <input value={q} onChange={(e) => setQ(e.target.value)} style={{ width: '100%' }} />
        </div>
        <button className="btn" onClick={() => setQ(PAYLOAD)} disabled={busy}>
          XSS Payload'ı Doldur
        </button>
        <button className="btn primary" onClick={run} disabled={busy}>
          Ara (iki sürüme)
        </button>
      </div>

      {results.vulnerable &&
        (vulnRaw ? (
          <div className="banner leak">🔓 Reflected XSS — vulnerable yanıtta &lt;script&gt; ham yansıdı; tarayıcıda çalışır.</div>
        ) : (
          <div className="banner safe">🔒 Ham script yok — payload girmeyi deneyin.</div>
        ))}
      {results.fixed && (
        <div className="banner safe">🔒 Fixed: html.escape ile kodlandı (&amp;lt;script&amp;gt;, tek tırnak &amp;#x27;) — çalışmaz.</div>
      )}

      <div className="compare">
        <XssPanel title="Vulnerable" response={results.vulnerable} />
        <XssPanel title="Fixed" response={results.fixed} />
      </div>

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
