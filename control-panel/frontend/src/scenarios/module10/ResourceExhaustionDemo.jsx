import { useState } from 'react'
import { proxy, MODULE10 } from '../../api.js'
import { HowItWorks } from '../../ui.jsx'

const SENARYO = '01-resource-exhaustion-dos'
const BAD_COUNT = 5
const BENIGN_FILE = 'gecerli.txt'

const STEPS = [
  'Her /upload isteği havuzdan bir kaynak (dosya handle\'ı) ayırır; havuz boyutu 5\'tir.',
  'Vulnerable: işlem sırasında istisna fırlarsa kaynak SERBEST BIRAKILMAZ — release_resource() try bloğunun SONRASINDA durur, istisnada o satıra hiç ulaşılmaz.',
  'Cleanup "mutlu yola" (happy path) bağlanmıştır: geliştirici istisnayı yakalamıştır ama yan etkisini (ayrılmış kaynağı) düşünmemiştir.',
  'Her hatalı istek bir slot sızdırır; 5 hatalı istekten sonra havuz dolar ve MEŞRU istekler de 503 alır → kalıcı DoS.',
  'Fixed: @contextmanager + finally ile kaynak HER çıkış yolunda bırakılır (normal dönüş, return, istisna). Cleanup\'ı hatırlamak yerine kaynağın kendi tanımına taşımak, hata sınıfını yapısal olarak imkânsız kılar.',
]

const VULN_CODE = `@app.post("/upload")
def upload(req: UploadRequest):
    handle = acquire_resource(req.filename)   # kaynak ayrıldı
    try:
        result = process_upload(req.filename)
    except ValueError as e:
        # ZAFIYET: kaynak SERBEST BIRAKILMIYOR — finally bloğu YOK
        raise HTTPException(status_code=400, detail=f"Yükleme başarısız: {e}")

    release_resource(handle)   # yalnızca BAŞARILI yolda çalışır`

const FIXED_CODE = `@contextmanager
def managed_resource(filename: str):
    """FIX: kaynak ayrılır ve çıkışta HER DURUMDA serbest bırakılır (istisna dahil)."""
    ...
    LOCKED_RESOURCES.append(handle)
    try:
        yield handle
    finally:
        # Bu blok, istisna fırlasa bile ÇALIŞIR → kaynak sızıntısı imkânsız.
        if handle in LOCKED_RESOURCES:
            LOCKED_RESOURCES.remove(handle)

@app.post("/upload")
def upload(req: UploadRequest):
    with managed_resource(req.filename) as handle:
        try:
            result = process_upload(req.filename)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Yükleme başarısız: {e}")`

function statusColor(s) {
  if (s >= 200 && s < 300) return '#7CFFB2'
  return '#ff9aa0'
}

function Panel({ title, cls, rows, status, benign }) {
  return (
    <div className={cls}>
      <h3>{title}</h3>
      {!rows.length ? (
        <div className="muted">Henüz istek atılmadı.</div>
      ) : (
        <>
          <ol className="steps">
            {rows.map((r) => (
              <li key={r.i}>
                <code>corrupt_{r.i}.txt</code> → <b style={{ color: statusColor(r.status) }}>{r.status}</b>
              </li>
            ))}
          </ol>
          {status && (
            <div className="statusline">
              kilitli kaynak:{' '}
              <b style={{ color: (status.data?.locked_count ?? 0) > 0 ? '#ff9aa0' : '#7CFFB2', fontSize: 16 }}>
                {status.data?.locked_count}
              </b>{' '}
              / {status.data?.pool_size} · kullanılabilir: <b>{status.data?.available}</b>
            </div>
          )}
          {status && <pre>{JSON.stringify(status.data, null, 2)}</pre>}
          {benign && (
            <>
              <div className="statusline" style={{ marginTop: 8 }}>
                Meşru dosya (<code>{BENIGN_FILE}</code>) →{' '}
                <b style={{ color: statusColor(benign.status) }}>HTTP {benign.status}</b>
              </div>
              <pre>{JSON.stringify(benign.data, null, 2)}</pre>
            </>
          )}
        </>
      )}
    </div>
  )
}

export default function ResourceExhaustionDemo() {
  const [vRows, setVRows] = useState([])
  const [fRows, setFRows] = useState([])
  const [vStatus, setVStatus] = useState(null)
  const [fStatus, setFStatus] = useState(null)
  const [vBenign, setVBenign] = useState(null)
  const [fBenign, setFBenign] = useState(null)
  const [busy, setBusy] = useState(false)

  async function sendBad() {
    setBusy(true)
    setVRows([]); setFRows([]); setVStatus(null); setFStatus(null); setVBenign(null); setFBenign(null)

    const v = []
    for (let i = 1; i <= BAD_COUNT; i++) {
      const r = await proxy('vulnerable', MODULE10, SENARYO, 'upload', {
        method: 'POST', body: { filename: `corrupt_${i}.txt` },
      })
      v.push({ i, status: r.status })
      setVRows([...v])
    }
    setVStatus(await proxy('vulnerable', MODULE10, SENARYO, 'resource-status'))

    const f = []
    for (let i = 1; i <= BAD_COUNT; i++) {
      const r = await proxy('fixed', MODULE10, SENARYO, 'upload', {
        method: 'POST', body: { filename: `corrupt_${i}.txt` },
      })
      f.push({ i, status: r.status })
      setFRows([...f])
    }
    setFStatus(await proxy('fixed', MODULE10, SENARYO, 'resource-status'))
    setBusy(false)
  }

  async function tryBenign() {
    setBusy(true)
    setVBenign(await proxy('vulnerable', MODULE10, SENARYO, 'upload', { method: 'POST', body: { filename: BENIGN_FILE } }))
    setFBenign(await proxy('fixed', MODULE10, SENARYO, 'upload', { method: 'POST', body: { filename: BENIGN_FILE } }))
    setBusy(false)
  }

  const vExhausted = vStatus && vStatus.data?.available === 0
  const fClean = fStatus && fStatus.data?.locked_count === 0

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 1 — Kaynak Tükenmesi (DoS)</h2>
        <div className="meta">CVSS 7.5 (High) · CWE-404 / CWE-772 · A10:2025</div>
        <p>
          Her <code>/upload</code> havuzdan bir kaynak ayırır. Vulnerable'da istisna oluştuğunda kaynak
          serbest bırakılmaz (<code>finally</code> yok) — her hatalı istek bir slot sızdırır ve havuz
          dolunca <b>meşru istekler de reddedilir</b>. Fixed sürüm context manager ile garantili cleanup yapar.
        </p>
      </header>

      <div className="actionbar">
        <button className="btn primary" onClick={sendBad} disabled={busy}>
          {busy ? 'Gönderiliyor…' : `${BAD_COUNT} Hatalı Dosya Yükle (iki sürüme)`}
        </button>
        <button className="btn" onClick={tryBenign} disabled={busy || !vRows.length}>
          Meşru Dosya Dene ({BENIGN_FILE})
        </button>
      </div>

      {vExhausted && (
        <div className="banner leak">
          🔓 Kaynaklar tükendi (DoS) — {BAD_COUNT} hatalı istek {vStatus.data.locked_count} kaynağı kalıcı olarak kilitledi,
          kullanılabilir slot: <b>0</b>.
        </div>
      )}
      {fClean && (
        <div className="banner safe">
          🔒 Kaynaklar her zaman serbest bırakıldı — aynı {BAD_COUNT} hatalı istekten sonra kilitli kaynak: <b>0</b>,
          havuz tam kapasitede.
        </div>
      )}
      {vBenign && (
        vBenign.status === 503 ? (
          <div className="banner leak">🔓 Meşru istek de reddedildi (HTTP 503) — servis kullanılamıyor.</div>
        ) : (
          <div className="banner neutral">Vulnerable meşru istek: HTTP {vBenign.status}</div>
        )
      )}
      {fBenign && (
        fBenign.status === 200 ? (
          <div className="banner safe">🔒 Fixed'de meşru istek çalışıyor (HTTP 200) — DoS oluşmadı.</div>
        ) : (
          <div className="banner neutral">Fixed meşru istek: HTTP {fBenign.status}</div>
        )
      )}

      <div className="compare">
        <Panel title="Vulnerable — cleanup yok" cls={vExhausted ? 'panel allowed' : 'panel'} rows={vRows} status={vStatus} benign={vBenign} />
        <Panel title="Fixed — try/finally (context manager)" cls={fClean ? 'panel blocked' : 'panel'} rows={fRows} status={fStatus} benign={fBenign} />
      </div>

      <div className="note" style={{ marginTop: 12 }}>
        ℹ️ Vulnerable sürümde <code>/reset</code> yoktur — <b>kaynaklar kendiliğinden geri gelmez</b> (zafiyetin özü budur).
        Tekrar denemek için senaryoyu panelden durdurup yeniden başlatın; aksi halde havuz zaten dolu olduğundan
        istekler doğrudan <code>503</code> alır.
      </div>

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
