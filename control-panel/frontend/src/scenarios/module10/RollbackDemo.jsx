import { useState } from 'react'
import { proxy, MODULE10 } from '../../api.js'
import { HowItWorks } from '../../ui.jsx'

const SENARYO = '04-transaction-integrity-no-rollback'

const STEPS = [
  'Transfer üç adımlıdır: (1) gönderenin bakiyesi düşürülür, (2) alıcı doğrulanır, (3) alıcının bakiyesi artırılır.',
  'Vulnerable: adım 1 UYGULANDIKTAN sonra adım 2\'de istisna fırlarsa, adım 1 GERİ ALINMAZ.',
  'Sonuç: para gönderenden düşer ama alıcıya hiç ulaşmaz — sistemden KAYBOLUR ve toplam bakiye azalır (tutarsız durum).',
  'ACID\'in "Atomicity" ilkesi ihlal edilir: bir işlem YA TAMAMEN uygulanır YA DA HİÇ — arada bir durum olamaz.',
  'Fixed: işlem öncesi snapshot alınır (BEGIN), herhangi bir adımda istisna olursa tüm değişiklikler geri yüklenir (ROLLBACK) ve istisna yeniden yükseltilir; yalnızca tüm adımlar başarılıysa kalıcı olur (COMMIT).',
]

const VULN_CODE = `# --- ADIM 1: gönderenin bakiyesini düşür (UYGULANDI) ---
ACCOUNTS[req.from_account] -= req.amount

# --- ADIM 2: alıcıyı doğrula (HATA NOKTASI) ---
if req.to_account not in ACCOUNTS:
    # ZAFIYET: istisna fırlıyor ama ADIM 1 GERİ ALINMIYOR
    raise HTTPException(404, f"Alıcı hesap bulunamadı: {req.to_account}")

# --- ADIM 3: alıcının bakiyesini artır (HİÇ ÇALIŞMAZ) ---
ACCOUNTS[req.to_account] += req.amount`

const FIXED_CODE = `snapshot = dict(ACCOUNTS)          # BEGIN TRANSACTION karşılığı
try:
    ACCOUNTS[req.from_account] -= req.amount        # ADIM 1
    if req.to_account not in ACCOUNTS:              # ADIM 2 (hata noktası)
        raise HTTPException(404, f"Alıcı hesap bulunamadı: {req.to_account}")
    ACCOUNTS[req.to_account] += req.amount          # ADIM 3
except Exception:
    ACCOUNTS.clear(); ACCOUNTS.update(snapshot)     # ROLLBACK — tüm adımlar geri alınır
    raise                                           # istisna yeniden yükseltilir
# buraya yalnızca tüm adımlar başarılıysa ulaşılır  # COMMIT karşılığı`

function Panel({ title, cls, transfer, balance, total, fromAccount }) {
  if (!transfer) {
    return (
      <div className="panel">
        <h3>{title}</h3>
        <div className="muted">Henüz transfer denenmedi.</div>
      </div>
    )
  }
  const consistent = total?.data?.consistent
  return (
    <div className={cls}>
      <h3>
        {title}{' '}
        <span className="badge" style={{ color: consistent ? '#7CFFB2' : '#ff9aa0' }}>
          {consistent ? 'tutarlı' : 'TUTARSIZ'}
        </span>
      </h3>
      <div className="statusline">
        POST /transfer → <b style={{ color: '#ff9aa0' }}>HTTP {transfer.status}</b>
      </div>
      <pre>{JSON.stringify(transfer.data, null, 2)}</pre>
      {balance && (
        <div className="statusline" style={{ marginTop: 8 }}>
          <code>{fromAccount}</code> bakiyesi:{' '}
          <b style={{ color: balance.data?.balance === 1000 ? '#7CFFB2' : '#ff9aa0', fontSize: 16 }}>
            {balance.data?.balance}
          </b>{' '}
          <span className="muted">(başlangıç: 1000)</span>
        </div>
      )}
      {total && (
        <>
          <div className="statusline">
            toplam bakiye:{' '}
            <b style={{ color: consistent ? '#7CFFB2' : '#ff9aa0', fontSize: 16 }}>{total.data?.total_balance}</b>{' '}
            / beklenen {total.data?.expected_total}
          </div>
          <pre>{JSON.stringify(total.data, null, 2)}</pre>
        </>
      )}
    </div>
  )
}

export default function RollbackDemo() {
  const [fromAccount, setFromAccount] = useState('alice')
  const [toAccount, setToAccount] = useState('gecersiz_hesap')
  const [amount, setAmount] = useState(100)
  const [vuln, setVuln] = useState({})
  const [fixed, setFixed] = useState({})
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    const results = {}
    for (const variant of ['vulnerable', 'fixed']) {
      // Deterministik başlangıç için bakiyeleri sıfırla.
      await proxy(variant, MODULE10, SENARYO, 'reset', { method: 'POST' })
      const transfer = await proxy(variant, MODULE10, SENARYO, 'transfer', {
        method: 'POST',
        body: { from_account: fromAccount, to_account: toAccount, amount: Number(amount) },
      })
      const balance = await proxy(variant, MODULE10, SENARYO, `balance/${encodeURIComponent(fromAccount)}`)
      const total = await proxy(variant, MODULE10, SENARYO, 'total')
      results[variant] = { transfer, balance, total }
    }
    setVuln(results.vulnerable)
    setFixed(results.fixed)
    setBusy(false)
  }

  const vLost = vuln.total && vuln.total.data?.consistent === false
  const fSafe = fixed.total && fixed.total.data?.consistent === true && fixed.transfer
  const lostAmount = vLost ? (vuln.total.data.expected_total - vuln.total.data.total_balance) : 0

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 4 — İşlem Bütünlüğü (Rollback Eksikliği)</h2>
        <div className="meta">CVSS 7.5 (High) · CWE-460 · A10:2025</div>
        <p>
          Çok adımlı transfer sırasında gönderenin bakiyesi düşürüldükten <b>sonra</b> alıcı doğrulamasında
          istisna oluşursa, vulnerable sürümde ilk adım <b>geri alınmaz</b> — para gönderenden düşer, alıcıya
          ulaşmaz, sistemden kaybolur. Fixed sürüm snapshot + rollback ile işlemi atomik yapar.
        </p>
      </header>

      <div className="actionbar">
        <div className="field">
          <label>Gönderen</label>
          <input value={fromAccount} onChange={(e) => setFromAccount(e.target.value)} style={{ minWidth: 100 }} />
        </div>
        <div className="field">
          <label>Alıcı (geçersiz)</label>
          <input value={toAccount} onChange={(e) => setToAccount(e.target.value)} style={{ minWidth: 150 }} />
        </div>
        <div className="field">
          <label>Tutar</label>
          <input type="number" value={amount} onChange={(e) => setAmount(e.target.value)} style={{ width: 90 }} />
        </div>
        <button className="btn primary" onClick={run} disabled={busy}>
          {busy ? 'Deneniyor…' : 'Transfer Dene (iki sürüme)'}
        </button>
      </div>

      {vLost && (
        <div className="banner leak">
          🔓 Para kayboldu — rollback yok: transfer <b>başarısız</b> ({vuln.transfer.status}) olmasına rağmen{' '}
          <code>{fromAccount}</code> bakiyesi <b>{vuln.balance?.data?.balance}</b>'a düştü. Toplam{' '}
          {vuln.total.data.expected_total} → <b>{vuln.total.data.total_balance}</b> ({lostAmount} TL sistemden kayboldu,{' '}
          <code>consistent: false</code>).
        </div>
      )}
      {fSafe && (
        <div className="banner safe">
          🔒 İşlem geri alındı (rollback) — aynı hata ({fixed.transfer.status}) alındı ama{' '}
          <code>{fromAccount}</code> bakiyesi <b>{fixed.balance?.data?.balance}</b> (değişmedi) ve toplam{' '}
          <b>{fixed.total.data.total_balance}</b> korundu (<code>consistent: true</code>).
        </div>
      )}

      <div className="compare">
        <Panel title="Vulnerable — rollback yok" cls={vLost ? 'panel allowed' : 'panel'} {...vuln} fromAccount={fromAccount} />
        <Panel title="Fixed — atomik (snapshot + rollback)" cls={fSafe ? 'panel blocked' : 'panel'} {...fixed} fromAccount={fromAccount} />
      </div>

      <div className="note" style={{ marginTop: 12 }}>
        💡 Her çalıştırmadan önce iki sürümde de <code>POST /reset</code> çağrılır (deterministik başlangıç:
        alice 1000, bob 500). Geçerli bir alıcı (<code>bob</code>) yazarsanız her iki sürüm de başarılı olur —
        fark yalnızca <b>hata yolunda</b> ortaya çıkar.
      </div>

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
