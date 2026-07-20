import { useState } from 'react'
import { proxy, MODULE05 } from '../../api.js'
import { HowItWorks } from '../../ui.jsx'

const SENARYO = '01-sql-injection-string-concatenation'
const PAYLOAD = "1' OR '1'='1"

const STEPS = [
  'Endpoint, id parametresini f-string ile doğrudan SQL sorgusuna gömüyor: WHERE id = \'{id}\'.',
  'Parametreleme olmadığından girdi VERİ değil, SORGUNUN parçası olarak yorumlanıyor.',
  "1' OR '1'='1 payload'ı WHERE koşulunu her satır için doğru yapar (OR '1'='1').",
  'Sonuç: WHERE filtresi anlamsızlaşır ve tablodaki TÜM hesaplar döner.',
  'Fixed sürüm ? placeholder + değer tuple\'ı kullanır; sürücü girdiyi yalnızca değer olarak bağlar, aynı payload boş sonuç verir.',
]

const VULN_CODE = `@app.get("/api/accounts")
def get_accounts(id: str):
    # ZAFIYET: id f-string ile sorguya gömülüyor — parametreleme yok.
    query = f"SELECT id, name, email, balance FROM accounts WHERE id = '{id}'"
    conn = get_db_connection()
    rows = conn.execute(query).fetchall()
    conn.close()
    return {"query": query, "results": [dict(r) for r in rows]}`

const FIXED_CODE = `@app.get("/api/accounts")
def get_accounts(id: str):
    # FIX: Parametreli sorgu. Girdi yalnızca DEĞER olarak bağlanır.
    query = "SELECT id, name, email, balance FROM accounts WHERE id = ?"
    conn = get_db_connection()
    rows = conn.execute(query, (id,)).fetchall()
    conn.close()
    return {"query": query, "results": [dict(r) for r in rows]}`

function SqlPanel({ title, response }) {
  if (!response) {
    return (
      <div className="panel">
        <h3>{title}</h3>
        <div className="muted">Henüz istek atılmadı.</div>
      </div>
    )
  }
  const data = response.data || {}
  const count = Array.isArray(data.results) ? data.results.length : 0
  const leaked = count > 1
  const cls = leaked ? 'panel allowed' : 'panel blocked'
  return (
    <div className={cls}>
      <h3>
        {title} <span className="badge">{count} hesap</span>
      </h3>
      <div className="statusline">HTTP {response.status}</div>
      {data.query && (
        <pre className={/\bOR\b|'1'='1'/.test(data.query) ? 'keyline' : undefined}>{data.query}</pre>
      )}
      <pre>{JSON.stringify(data.results, null, 2)}</pre>
    </div>
  )
}

export default function SqlInjectionDemo() {
  const [id, setId] = useState('1')
  const [results, setResults] = useState({})
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      next[v] = await proxy(v, MODULE05, SENARYO, `api/accounts?id=${encodeURIComponent(id)}`)
    }
    setResults(next)
    setBusy(false)
  }

  const vulnCount = Array.isArray(results.vulnerable?.data?.results) ? results.vulnerable.data.results.length : null

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 1 — SQL Injection / String Concatenation</h2>
        <div className="meta">CVSS 7.5 (High) · CWE-89 · A05:2025</div>
        <p>
          <code>id</code> parametresi f-string ile doğrudan SQL sorgusuna gömülüyor.{' '}
          <code>1' OR '1'='1</code> payload'ı WHERE koşulunu her zaman doğru yapıp tüm hesapları döndürür.
          Fixed sürüm parametreli sorgu (<code>WHERE id = ?</code>) kullanır.
        </p>
      </header>

      <div className="actionbar">
        <div className="field">
          <label>Hesap ID</label>
          <input value={id} onChange={(e) => setId(e.target.value)} style={{ minWidth: 200 }} />
        </div>
        <button className="btn" onClick={() => setId(PAYLOAD)} disabled={busy}>
          Enjeksiyon Payload'ı Doldur
        </button>
        <button className="btn primary" onClick={run} disabled={busy}>
          Sorgula (iki sürüme)
        </button>
      </div>

      {vulnCount !== null &&
        (vulnCount > 1 ? (
          <div className="banner leak">🔓 SQL Injection başarılı — vulnerable sürümde {vulnCount} hesap sızdı.</div>
        ) : (
          <div className="banner safe">🔒 Enjeksiyon etkisiz — tek/sıfır kayıt döndü.</div>
        ))}
      {results.fixed && (
        <div className="banner safe">
          🔒 Fixed: parametreli sorgu — {(results.fixed.data?.results?.length ?? 0)} kayıt (payload değer olarak bağlandı).
        </div>
      )}

      <div className="compare">
        <SqlPanel title="Vulnerable" response={results.vulnerable} />
        <SqlPanel title="Fixed" response={results.fixed} />
      </div>

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
