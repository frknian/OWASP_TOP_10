import { useState } from 'react'
import { proxy, MODULE10 } from '../../api.js'
import { HowItWorks } from '../../ui.jsx'

const SENARYO = '03-database-error-info-leak'
const BENIGN = '1'
// Farklı bozuk girdiler → vulnerable'da FARKLI hatalar (oracle); fixed'de hep aynı yanıt.
const PROBES = [
  { label: "Tek tırnak (')", value: "'" },
  { label: 'Harf (abc)', value: 'abc' },
  { label: 'Sözdizimi (1 AND)', value: '1 AND' },
  { label: 'Devasa sayı', value: '999999999999999999999' },
]

const STEPS = [
  'Vulnerable, oluşan sqlite hatasının TAM METNİNİ ve çalıştırılan sorguyu istemciye döndürür.',
  'Bu bir ORACLE\'dır: farklı bozuk girdiler FARKLI cevaplar üretir; saldırgan her cevaptan şemanın bir parçasını öğrenir.',
  "Keşif zinciri: 'abc' → \"no such column\" (girdi doğrudan gömülüyor) · \"'\" → \"unrecognized token\" (string birleştirme = SQLi sinyali) · '1 AND' → \"incomplete input\" (sorgu yapısı).",
  'executed_query alanı zaten tablo adını (customer_orders) ve tüm sütunları (customer_email...) açıkça verir — birkaç istekte şema haritalanır.',
  'Fixed iki katman: (1) girdi doğrulama + parametreli sorgu → hata çoğunlukla OLUŞMAZ; (2) tüm hatalar aynı jenerik 400\'e indirgenir → girdiler ayırt edilemez, oracle KAPANIR.',
]

const VULN_CODE = `query = f"SELECT order_id, customer_email, product_name, total_amount FROM customer_orders WHERE order_id = {order_id}"
try:
    rows = conn.execute(query).fetchall()
except sqlite3.Error as e:
    # ZAFIYET: DB hatasının TAM METNİ + çalıştırılan sorgu istemciye dönüyor.
    return JSONResponse(status_code=500, content={
        "db_error": str(e),           # ← sqlite'ın ham mesajı (sütun/tablo adları)
        "executed_query": query,      # ← sorgu yapısı da sızıyor
    })`

const FIXED_CODE = `# KATMAN 1: girdi doğrulaması + aralık kontrolü — bozuk değer DB'ye hiç ulaşmaz
try:
    parsed_id = int(order_id)
except ValueError:
    raise HTTPException(400, GENERIC_ERROR)          # her zaman AYNI mesaj
if not (INT64_MIN <= parsed_id <= INT64_MAX):
    raise HTTPException(400, GENERIC_ERROR)

try:
    rows = conn.execute("... WHERE order_id = ?", (parsed_id,))   # parametreli
except Exception as e:
    # KATMAN 2: sqlite3.Error DEĞİL, Exception yakalanır — OverflowError gibi
    # istisnaların farklı bir yanıta (500) dönüşmesi oracle'ı yeniden açardı.
    _log(f"ERROR db {type(e).__name__}: {e}")        # detay yalnızca SUNUCU log'una
    raise HTTPException(400, GENERIC_ERROR)`

function highlightSchema(text) {
  // Tablo/sütun adlarını görsel olarak vurgula (şema sızıntısının kanıtı).
  const KEYS = ['customer_orders', 'customer_email', 'product_name', 'total_amount', 'order_id']
  const parts = []
  let rest = String(text)
  let key = 0
  while (rest.length) {
    let idx = -1
    let found = null
    for (const k of KEYS) {
      const i = rest.indexOf(k)
      if (i !== -1 && (idx === -1 || i < idx)) { idx = i; found = k }
    }
    if (idx === -1) { parts.push(<span key={key++}>{rest}</span>); break }
    if (idx > 0) parts.push(<span key={key++}>{rest.slice(0, idx)}</span>)
    parts.push(
      <span key={key++} style={{ background: 'rgba(255,77,79,.28)', color: '#ffd0d1', borderRadius: 3, padding: '0 2px' }}>
        {found}
      </span>
    )
    rest = rest.slice(idx + found.length)
  }
  return parts
}

function Panel({ title, cls, rows, isVuln }) {
  return (
    <div className={cls}>
      <h3>{title}</h3>
      {!rows.length ? (
        <div className="muted">Henüz sorgu atılmadı.</div>
      ) : (
        rows.map((r, i) => (
          <div key={i} style={{ marginBottom: 10 }}>
            <div className="statusline">
              <code>order_id={r.probe}</code> → <b style={{ color: r.status === 200 ? '#7CFFB2' : '#ff9aa0' }}>HTTP {r.status}</b>
            </div>
            <pre style={{ whiteSpace: 'pre-wrap' }}>
              {isVuln ? highlightSchema(JSON.stringify(r.data, null, 2)) : JSON.stringify(r.data, null, 2)}
            </pre>
          </div>
        ))
      )}
    </div>
  )
}

export default function DbErrorLeakDemo() {
  const [orderId, setOrderId] = useState(BENIGN)
  const [vRows, setVRows] = useState([])
  const [fRows, setFRows] = useState([])
  const [busy, setBusy] = useState(false)

  async function query(values) {
    setBusy(true)
    const v = []
    const f = []
    for (const val of values) {
      const rv = await proxy('vulnerable', MODULE10, SENARYO, `api/orders?order_id=${encodeURIComponent(val)}`)
      v.push({ probe: val, status: rv.status, data: rv.data })
      setVRows([...v])
      const rf = await proxy('fixed', MODULE10, SENARYO, `api/orders?order_id=${encodeURIComponent(val)}`)
      f.push({ probe: val, status: rf.status, data: rf.data })
      setFRows([...f])
    }
    setBusy(false)
  }

  const vLeaked = vRows.some((r) => r.data?.executed_query || r.data?.db_error)
  // Fixed'de tüm bozuk girdilerin AYNI yanıtı verdiğini doğrula (oracle kapalı mı?)
  const fBad = fRows.filter((r) => r.status !== 200)
  const fUniform = fBad.length > 1 && new Set(fBad.map((r) => `${r.status}:${JSON.stringify(r.data)}`)).size === 1

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 3 — Veritabanı Hatası Üzerinden Bilgi Sızıntısı</h2>
        <div className="meta">CVSS 5.3 (Medium) · CWE-209 · A10:2025</div>
        <p>
          Bozuk <code>order_id</code> girdilerinde vulnerable sürüm <b>ham DB hatasını</b> ve çalıştırılan
          sorguyu döndürür; saldırgan farklı girdilerle farklı hatalar tetikleyerek şemayı adım adım
          haritalar. Fixed sürüm tüm hataları <b>tek bir jenerik yanıta</b> indirger.
        </p>
        <div className="note">
          🔗 <b>Modül 02/S3 ile ilişki:</b> Aynı prensip (CWE-209), farklı açı — orada sızan{' '}
          <i>framework stack trace + kütüphane sürümleri</i>, burada <i>şema/sorgu yapısı</i> ve odak,
          saldırganın tekrarlı tetiklemeyle bilgi topladığı <b>error-based keşif süreci</b>.
        </div>
      </header>

      <div className="actionbar">
        <div className="field">
          <label>order_id</label>
          <input value={orderId} onChange={(e) => setOrderId(e.target.value)} style={{ minWidth: 180 }} />
        </div>
        <button className="btn" onClick={() => setOrderId("'")} disabled={busy}>
          Bozuk Girdi Doldur (')
        </button>
        <button className="btn primary" onClick={() => query([orderId])} disabled={busy}>
          Sorgula (iki sürüme)
        </button>
        <button className="btn" onClick={() => query(PROBES.map((p) => p.value))} disabled={busy}>
          Keşif Zinciri Çalıştır (4 girdi)
        </button>
      </div>

      {vLeaked && (
        <div className="banner leak">
          🔓 Şema bilgisi sızdı — yanıtta ham DB hatası ve <code>executed_query</code> var; tablo adı{' '}
          <code>customer_orders</code> ve sütunlar (<code>customer_email</code>…) açıkça görünüyor (kırmızı vurgu).
        </div>
      )}
      {fUniform && (
        <div className="banner safe">
          🔒 Detaylar gizlendi — {fBad.length} farklı bozuk girdi <b>birebir aynı</b> yanıtı verdi
          (<code>400 {'{'}"detail":"Geçersiz istek"{'}'}</code>); girdiler ayırt edilemiyor, oracle kapalı.
        </div>
      )}

      <div className="compare">
        <Panel title="Vulnerable — ham DB hatası" cls={vLeaked ? 'panel allowed' : 'panel'} rows={vRows} isVuln />
        <Panel title="Fixed — jenerik hata" cls={fUniform ? 'panel blocked' : 'panel'} rows={fRows} />
      </div>

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
