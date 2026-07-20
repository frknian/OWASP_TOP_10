// Senaryolar arasında paylaşılan sade UI parçaları.
import { useState } from 'react'

// Açılır/kapanır "Nasıl Çalışır?" paneli: adım adım anlatım + vulnerable/fixed kod alıntısı.
export function HowItWorks({ steps, vulnCode, fixedCode }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="howitworks">
      <button className="btn" onClick={() => setOpen((o) => !o)}>
        {open ? '🔼 Gizle' : '🔍 Nasıl Çalışır?'}
      </button>
      {open && (
        <div className="how-body">
          <h4>Adım Adım Ne Oluyor?</h4>
          <ol className="steps">
            {steps.map((s, i) => (
              <li key={i}>{s}</li>
            ))}
          </ol>
          <h4>İlgili Kod</h4>
          <div className="codecompare">
            <div className="codecol vuln">
              <div className="codelabel">vulnerable</div>
              <pre><code>{vulnCode}</code></pre>
            </div>
            <div className="codecol fix">
              <div className="codelabel">fixed</div>
              <pre><code>{fixedCode}</code></pre>
            </div>
          </div>
          <div className="codenote">Not: uzun yorum blokları <code># ...</code> ile kısaltıldı; gösterilen kod satırları gerçek <code>main.py</code> dosyalarından birebir alınmıştır.</div>
        </div>
      )}
    </div>
  )
}

export function LoginBox({ username, password, setUsername, setPassword, onLogin, loginState, busy }) {
  return (
    <div className="loginbox">
      <div className="field">
        <label>Kullanıcı adı</label>
        <input value={username} onChange={(e) => setUsername(e.target.value)} />
      </div>
      <div className="field">
        <label>Parola</label>
        <input value={password} onChange={(e) => setPassword(e.target.value)} />
      </div>
      <button className="btn" onClick={onLogin} disabled={busy}>
        Giriş yap (iki sürüme)
      </button>
      {loginState.vulnerable && (
        <span className="loginstate">
          vulnerable: <b>{loginState.vulnerable}</b> · fixed: <b>{loginState.fixed}</b>
        </span>
      )}
    </div>
  )
}

// HTTP durumuna göre panel: 2xx → "erişim verildi" (kırmızı), 403 → "engellendi" (yeşil).
export function ResultPanel({ title, result }) {
  if (!result) {
    return (
      <div className="panel">
        <h3>{title}</h3>
        <div className="muted">Henüz istek atılmadı.</div>
      </div>
    )
  }
  const { status, data } = result
  const blocked = status === 403 || status === 401
  const allowed = status >= 200 && status < 300
  const cls = blocked ? 'panel blocked' : allowed ? 'panel allowed' : 'panel'
  const badge = blocked ? '🔒 Engellendi' : allowed ? '🔓 Erişim verildi' : `HTTP ${status}`
  return (
    <div className={cls}>
      <h3>
        {title} <span className="badge">{badge}</span>
      </h3>
      <div className="statusline">HTTP {status}</div>
      <pre>{typeof data === 'string' ? data : JSON.stringify(data, null, 2)}</pre>
    </div>
  )
}

// Senaryoya özel banner'lar: vulnerable erişim verdiyse "sızıntı", fixed 403/404 ise
// "engellendi", fixed 2xx ise (whitelist/doğru key gibi) meşru erişim mesajı.
export function ScenarioBanners({ results, vulnLeakMsg, fixedBlockMsg, fixedOkMsg }) {
  const v = results.vulnerable
  const f = results.fixed
  return (
    <>
      {v &&
        (v.ok ? (
          <div className="banner leak">🔓 {vulnLeakMsg}</div>
        ) : (
          <div className="banner neutral">Vulnerable: HTTP {v.status}</div>
        ))}
      {f &&
        (f.status === 403 || f.status === 404 ? (
          <div className="banner safe">🔒 {fixedBlockMsg}</div>
        ) : f.ok ? (
          <div className="banner neutral">{fixedOkMsg || `Fixed: HTTP ${f.status} (meşru erişim)`}</div>
        ) : (
          <div className="banner neutral">Fixed: HTTP {f.status}</div>
        ))}
    </>
  )
}

export function CompareGrid({ results }) {
  return (
    <div className="compare">
      <ResultPanel title="Vulnerable" result={results.vulnerable} />
      <ResultPanel title="Fixed" result={results.fixed} />
    </div>
  )
}

// Modül 03 senaryoları HER ZAMAN 200 döner; fark response BODY'sindedir. Body'de
// "[SİMÜLASYON]" geçiyorsa zafiyet tetiklenmiş demektir.
function _isTriggered(response) {
  if (!response) return false
  const text = typeof response.data === 'string' ? response.data : JSON.stringify(response.data)
  return text.includes('[SİMÜLASYON]')
}

export function SimBanner({ response }) {
  if (!response) return null
  return _isTriggered(response) ? (
    <div className="banner leak">🔓 Zafiyet tetiklendi (simülasyon)</div>
  ) : (
    <div className="banner safe">🔒 Güvenli — girdi yorumlanmadı</div>
  )
}

// Modül 03 için panel: renk, HTTP durumuna değil "[SİMÜLASYON]" içerip içermediğine göre.
function SimPanel({ title, response }) {
  const triggered = _isTriggered(response)
  const cls = !response ? 'panel' : triggered ? 'panel allowed' : 'panel blocked'
  return (
    <div className={cls}>
      <h3>{title}</h3>
      <SimBanner response={response} />
      {response ? (
        <>
          <div className="statusline">HTTP {response.status}</div>
          <pre>{typeof response.data === 'string' ? response.data : JSON.stringify(response.data, null, 2)}</pre>
        </>
      ) : (
        <div className="muted">Henüz istek atılmadı.</div>
      )}
    </div>
  )
}

export function SimCompareGrid({ results }) {
  return (
    <div className="compare">
      <SimPanel title="Vulnerable" response={results.vulnerable} />
      <SimPanel title="Fixed" response={results.fixed} />
    </div>
  )
}

// vulnerable erişim verdi + fixed engelledi → zafiyet net kanıtlandı.
export function LeakBanner({ results }) {
  const v = results.vulnerable
  const f = results.fixed
  if (!v || !f) return null
  const leak = v.ok && (f.status === 403 || f.status === 401)
  if (leak) {
    return <div className="banner leak">🔓 Zafiyet kanıtlandı: vulnerable erişim verdi, fixed engelledi (403).</div>
  }
  if (v.ok && f.ok) {
    return <div className="banner neutral">Her iki sürüm de erişim verdi — bu genelde meşru (kendi kaydına erişim) durumudur. ID'yi başka bir kullanıcınınkiyle değiştirip tekrar deneyin.</div>
  }
  return null
}
