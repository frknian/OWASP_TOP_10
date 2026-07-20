import { useState } from 'react'
import { proxy, MODULE05 } from '../../api.js'
import { HowItWorks } from '../../ui.jsx'

const SENARYO = '02-orm-injection-blind-trust'
const PAYLOAD = "x' OR '1'='1"

const STEPS = [
  'Uygulama bir MiniORM soyutlaması kullanıyor — ama ORM kullanmak tek başına güvenlik sağlamaz.',
  'MiniORM\'un iki metodu var: raw() (string concat, güvensiz) ve filter() (parametreli, güvenli).',
  'Vulnerable endpoint raw()\'ı kullanıcı girdisiyle çağırıyor → framework\'e "kör güven" (blind trust) sonucu SQL injection.',
  "x' OR '1'='1 payload'ı WHERE name = 'x' OR '1'='1' üretir → tüm kayıtlar döner.",
  'Fixed sürüm AYNI MiniORM sınıfının filter() metodunu kullanır — sınıf değişmedi, kullanım şekli değişti. Güvenlik framework\'ün varlığında değil, girdinin veri olarak geçirilmesinde.',
]

const VULN_CODE = `class MiniORM:
    def raw(self, where_fragment):      # GÜVENSİZ — fragment doğrudan gömülür
        query = f"SELECT ... FROM {self.table} WHERE {where_fragment}"
        ...
    def filter(self, column, value):    # GÜVENLİ — değer parametreli bağlanır
        query = f"SELECT ... FROM {self.table} WHERE {column} = ?"
        ... execute(query, (value,))

@app.get("/api/search")
def search(term: str):
    # ZAFIYET: GÜVENSİZ raw() metodu kullanıcı girdisiyle çağrılıyor.
    results, query = orm.raw(f"name = '{term}'")
    return {"query": query, "results": results}`

const FIXED_CODE = `@app.get("/api/search")
def search(term: str):
    # FIX: AYNI MiniORM, ama GÜVENLİ filter() metodu. term parametreli bağlanır.
    results, query = orm.filter("name", term)
    return {"query": query, "results": results}`

function OrmPanel({ title, response }) {
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
        {title} <span className="badge">{count} kayıt</span>
      </h3>
      <div className="statusline">HTTP {response.status}</div>
      {data.query && (
        <pre className={/\bOR\b|'1'='1'/.test(data.query) ? 'keyline' : undefined}>{data.query}</pre>
      )}
      <pre>{JSON.stringify(data.results, null, 2)}</pre>
    </div>
  )
}

export default function OrmInjectionDemo() {
  const [term, setTerm] = useState('Alice')
  const [results, setResults] = useState({})
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      next[v] = await proxy(v, MODULE05, SENARYO, `api/search?term=${encodeURIComponent(term)}`)
    }
    setResults(next)
    setBusy(false)
  }

  const vulnCount = Array.isArray(results.vulnerable?.data?.results) ? results.vulnerable.data.results.length : null

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 2 — ORM Injection / Blind Trust in Frameworks</h2>
        <div className="meta">CVSS 7.5 (High) · CWE-89 · A05:2025</div>
        <p>
          MiniORM soyutlaması var, ama vulnerable endpoint güvensiz <code>raw()</code> metodunu kullanıcı
          girdisiyle çağırıyor → yine SQL injection. Fixed sürüm <b>aynı sınıfın</b> parametreli{' '}
          <code>filter()</code> metodunu kullanır. Ders: ORM kullanmak otomatik güvenlik sağlamaz.
        </p>
      </header>

      <div className="actionbar">
        <div className="field">
          <label>Arama terimi</label>
          <input value={term} onChange={(e) => setTerm(e.target.value)} style={{ minWidth: 200 }} />
        </div>
        <button className="btn" onClick={() => setTerm(PAYLOAD)} disabled={busy}>
          Enjeksiyon Payload'ı Doldur
        </button>
        <button className="btn primary" onClick={run} disabled={busy}>
          Ara (iki sürüme)
        </button>
      </div>

      {vulnCount !== null &&
        (vulnCount > 1 ? (
          <div className="banner leak">🔓 SQL Injection başarılı — vulnerable (raw()) sürümde {vulnCount} kayıt sızdı.</div>
        ) : (
          <div className="banner safe">🔒 Enjeksiyon etkisiz — tek/sıfır kayıt döndü.</div>
        ))}
      {results.fixed && (
        <div className="banner safe">
          🔒 Fixed: filter() parametreli — {(results.fixed.data?.results?.length ?? 0)} kayıt (aynı sınıf, güvenli kullanım).
        </div>
      )}

      <div className="compare">
        <OrmPanel title="Vulnerable — raw()" response={results.vulnerable} />
        <OrmPanel title="Fixed — filter()" response={results.fixed} />
      </div>

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
