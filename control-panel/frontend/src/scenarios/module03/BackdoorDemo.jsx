import { useState } from 'react'
import { proxy, MODULE03 } from '../../api.js'
import { SimCompareGrid, HowItWorks } from '../../ui.jsx'

const SENARYO = '02-conditional-backdoor-bybit-style'
const TRIGGER = '0xC0FFEE_TREASURY_MULTISIG'

const STEPS = [
  'Uygulama, transferleri "imzalamak" için üçüncü taraf wallet_helper kütüphanesine güveniyor.',
  'Kütüphane %99 zaman kusursuz çalışıyor — normal alıcılarda hiçbir anormallik yok, bu yüzden testleri ve kod incelemesini geçer.',
  'Ama saldırganın gizlice gömdüğü ÖZEL bir alıcı adresi geçtiğinde koşullu backdoor devreye girer.',
  `Tetikleyici adres (${TRIGGER}) ile transferde: gerçek saldırıda alıcı sessizce saldırgan cüzdanıyla değiştirilip imzalanırdı; burada defanged olarak [SİMÜLASYON] backdoor kaydı döner.`,
  'Fixed sürüm, backdoor\'u tespit edilip kaldırılmış temiz/imzalı bir sürümdür: koşullu dallanma yok, aynı tetikleyici adres artık hiçbir gizli davranışa yol açmaz.',
]

const VULN_CODE = `_BACKDOOR_TRIGGER_RECIPIENT = "0xC0FFEE_TREASURY_MULTISIG"
_ATTACKER_ADDRESS = "0xDEADBEEF_ATTACKER_WALLET"


def process_transaction(tx: dict) -> dict:
    recipient = tx.get("recipient", "")
    amount = tx.get("amount", 0)

    if recipient == _BACKDOOR_TRIGGER_RECIPIENT:
        # --- BACKDOOR AKTİF (DEFANGED) ---
        return {
            "signed": True,
            "recipient": recipient,
            "amount": amount,
            "backdoor": "[SİMÜLASYON] Backdoor aktive oldu: ...",
        }

    return {"signed": True, "recipient": recipient, "amount": amount}`

const FIXED_CODE = `def process_transaction(tx: dict) -> dict:
    # FIX: Koşullu dallanma yok, gizli alıcı kontrolü yok. Her işlem aynı şekilde
    # işlenir; girdiye bağlı gizli davranış imkânsız.
    return {
        "signed": True,
        "recipient": tx.get("recipient", ""),
        "amount": tx.get("amount", 0),
    }`

export default function BackdoorDemo() {
  const [recipient, setRecipient] = useState('0xALICE_NORMAL_USER')
  const [amount, setAmount] = useState('100')
  const [results, setResults] = useState({})
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      next[v] = await proxy(v, MODULE03, SENARYO, 'transfer', {
        method: 'POST',
        body: { recipient, amount: Number(amount) },
      })
    }
    setResults(next)
    setBusy(false)
  }

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 2 — Conditional Backdoor / Bybit tarzı</h2>
        <div className="meta">CVSS 9.8 (Critical) · CWE-1395 / CWE-506 · A03:2025 · DEFANGED simülasyon</div>
        <p>
          Bağımlılığın içinde <b>koşullu</b> bir backdoor var: yalnızca gizli bir tetikleyici alıcı
          adresinde devreye giriyor. Normal alıcıyla gönderdiğinizde iki sürüm de aynı davranır; tetikleyici
          adresle vulnerable sürümde backdoor uyanır, fixed sürümde uyanmaz.
        </p>
      </header>

      <div className="actionbar">
        <div className="field" style={{ flex: 1, minWidth: 260 }}>
          <label>Alıcı adresi</label>
          <input value={recipient} onChange={(e) => setRecipient(e.target.value)} style={{ width: '100%' }} />
        </div>
        <div className="field">
          <label>Miktar</label>
          <input value={amount} onChange={(e) => setAmount(e.target.value)} style={{ width: 90 }} />
        </div>
        <button className="btn" onClick={() => setRecipient(TRIGGER)} disabled={busy}>
          Tetikleyici Adresi Doldur
        </button>
        <button className="btn primary" onClick={run} disabled={busy}>
          Transfer Gönder (iki sürüme)
        </button>
      </div>

      <SimCompareGrid results={results} />
      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
