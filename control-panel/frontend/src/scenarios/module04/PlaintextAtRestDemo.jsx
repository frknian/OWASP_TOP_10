import { useState } from 'react'
import { proxy, MODULE04 } from '../../api.js'
import { CompareGrid, ResultPanel, HowItWorks } from '../../ui.jsx'

const SENARYO = '03-plaintext-data-at-rest'

const STEPS = [
  'Vulnerable sürüm, hassas kimlik alanını (national_id) veritabanına DÜZ METİN yazıyor.',
  'Uygulama çalışırken erişim kontrolü olsa bile, veri disk üzerinde korumasız: DB dosyasına/yedeğe/snapshot\'a veya bir SQLi\'ye erişen düz metni okur.',
  'GET /admin/db-dump ham satırları gösterir: vulnerable\'da national_id düz metin, fixed\'de national_id_enc ciphertext (gAAAA...).',
  'Fixed sürüm, alanı Fernet ile şifreleyip öyle saklar; çözme yalnızca yetkili GET /customers/{id} isteğinde, sunucu tarafında yapılır.',
  'Anahtar yönetimi Senaryo 2\'nin dersini uygular: anahtar kaynağa gömülmez, ENCRYPTION_KEY ortam değişkeninden gelir (panel bu anahtarı backend başlatırken enjekte eder).',
]

const VULN_CODE = `def create_customer(customer: Customer):
    # ZAFIYET: national_id düz metin olarak yazılıyor.
    conn = get_db_connection()
    cur = conn.execute(
        "INSERT INTO customers (name, national_id) VALUES (?, ?)",
        (customer.name, customer.national_id),
    )
    conn.commit()
    ...
    return {"id": customer_id, "name": customer.name, "national_id": customer.national_id}`

const FIXED_CODE = `def create_customer(customer: Customer):
    # FIX: national_id şifrelenerek yazılır; DB'de yalnızca ciphertext durur.
    enc = fernet.encrypt(customer.national_id.encode("utf-8")).decode("utf-8")
    conn.execute("INSERT INTO customers (name, national_id_enc) VALUES (?, ?)", (customer.name, enc))
    ...

def read_customer(customer_id: int):
    # Çözme yalnızca yetkili sunucu tarafında, meşru istekte.
    national_id = fernet.decrypt(row["national_id_enc"].encode("utf-8")).decode("utf-8")
    return {"id": row["id"], "name": row["name"], "national_id": national_id}`

export default function PlaintextAtRestDemo() {
  const [name, setName] = useState('Ayşe Yılmaz')
  const [nationalId, setNationalId] = useState('12345678901')
  const [createResults, setCreateResults] = useState({})
  const [dumpResults, setDumpResults] = useState({})
  const [readResult, setReadResult] = useState(null)
  const [fixedId, setFixedId] = useState(null)
  const [busy, setBusy] = useState(false)

  async function createRecord() {
    setBusy(true)
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      next[v] = await proxy(v, MODULE04, SENARYO, 'customers', {
        method: 'POST',
        body: { name, national_id: nationalId },
      })
    }
    setCreateResults(next)
    if (next.fixed && next.fixed.ok && next.fixed.data && next.fixed.data.id) {
      setFixedId(next.fixed.data.id)
    }
    setBusy(false)
  }

  async function dump() {
    setBusy(true)
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      next[v] = await proxy(v, MODULE04, SENARYO, 'admin/db-dump')
    }
    setDumpResults(next)
    setBusy(false)
  }

  async function readAuthorized() {
    if (!fixedId) return
    setBusy(true)
    setReadResult(await proxy('fixed', MODULE04, SENARYO, `customers/${fixedId}`))
    setBusy(false)
  }

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 3 — Plaintext Sensitive Data at Rest</h2>
        <div className="meta">CVSS 6.5 (Medium) · CWE-311 / CWE-312 · A04:2025</div>
        <p>
          Hassas kimlik alanı (sahte "TC Kimlik No") vulnerable sürümde düz metin saklanıyor; fixed sürümde
          Fernet ile şifreleniyor. Kayıt oluşturup DB dump'ını karşılaştırın, sonra fixed'de yetkili okumayla
          çözülmüş halini görün.
        </p>
        <div className="note">
          ℹ️ national_id değeri gerçek değildir, yalnızca demo amaçlıdır.
        </div>
      </header>

      <div className="actionbar">
        <div className="field">
          <label>Ad Soyad</label>
          <input value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <div className="field">
          <label>TC Kimlik No (sahte)</label>
          <input value={nationalId} onChange={(e) => setNationalId(e.target.value)} />
        </div>
        <button className="btn primary" onClick={createRecord} disabled={busy}>
          Kayıt Oluştur (iki sürüme)
        </button>
      </div>
      <CompareGrid results={createResults} />

      <div className="actionbar" style={{ marginTop: 20 }}>
        <button className="btn primary" onClick={dump} disabled={busy}>
          DB Dump'ı Görüntüle (iki sürüme) → GET /admin/db-dump
        </button>
      </div>
      {dumpResults.vulnerable && (
        <div className="banner leak">🔓 Vulnerable: düz metin saklanıyor — national_id DB'de açık okunuyor.</div>
      )}
      {dumpResults.fixed && (
        <div className="banner safe">🔒 Fixed: şifreli saklanıyor — DB'de yalnızca national_id_enc (ciphertext) var.</div>
      )}
      <CompareGrid results={dumpResults} />

      <div className="actionbar" style={{ marginTop: 20 }}>
        <button className="btn" onClick={readAuthorized} disabled={busy || !fixedId}>
          Yetkili Olarak Oku (sadece fixed) → GET /customers/{fixedId || '{id}'}
        </button>
        <span className="tip">Önce fixed'de kayıt oluşturun; sunucu, ciphertext'i çözüp düz metni döndürür.</span>
      </div>
      {readResult && (
        <div className="compare">
          <ResultPanel title="Fixed — yetkili okuma (çözülmüş)" result={readResult} />
          <div className="panel">
            <h3>Not</h3>
            <div className="muted">
              Aynı kayıt DB'de ciphertext olarak duruyor; yalnızca bu yetkili endpoint, sunucu tarafında anahtarla
              çözüp düz metni döndürüyor.
            </div>
          </div>
        </div>
      )}

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
