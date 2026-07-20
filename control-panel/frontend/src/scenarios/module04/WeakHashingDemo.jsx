import { useState } from 'react'
import { proxy, MODULE04 } from '../../api.js'
import { CompareGrid, ScenarioBanners, HowItWorks } from '../../ui.jsx'

const SENARYO = '01-weak-hashing-rainbow-table'

const STEPS = [
  'Vulnerable sürüm parolaları TUZSUZ MD5 ile hash\'liyor: aynı parola her kullanıcıda aynı hash\'i verir ve MD5 çok hızlıdır.',
  'Unutulmuş GET /debug/dump-hashes endpoint\'i, kimlik doğrulaması olmadan tüm username+hash çiftlerini döker.',
  'crack_demo.py (ayrı bir script, HTTP endpoint\'i değil) küçük bir yaygın-parola wordlist\'inin MD5\'lerini önceden hesaplar ve dökülen hash\'lerle eşleştirir — bir mini rainbow table.',
  'Tuz olmadığı için eşleşme birebir çalışır: seed parolaları anında kırılır → alice=123456, bob=password, carol=qwerty, dave=letmein.',
  'Fixed sürümde /debug/dump-hashes kaldırılmış (404) ve parolalar argon2id ile hash\'lenir: her hash\'te rastgele tuz + adaptif maliyet → rainbow table işlevsiz.',
]

const VULN_CODE = `def hash_password(plain_password: str) -> str:
    # ZAFIYET: Tuzsuz MD5 — aynı parola = aynı hash; MD5 çok hızlı → tabloyla anında geri çevrilir.
    return hashlib.md5(plain_password.encode("utf-8")).hexdigest()


@app.get("/debug/dump-hashes")
def dump_hashes():
    # ZAFIYET: Unutulmuş debug endpoint'i — kimlik doğrulama yok, tüm hash'leri döker.
    conn = get_db_connection()
    rows = conn.execute("SELECT username, password_hash FROM users").fetchall()
    conn.close()
    return {"users": [{"username": r["username"], "password_hash": r["password_hash"]} for r in rows]}`

const FIXED_CODE = `password_hasher = PasswordHasher()  # argon2id

def hash_password(plain_password: str) -> str:
    # FIX: argon2id — tuz otomatik ve rastgele, maliyet adaptif.
    return password_hasher.hash(plain_password)

# NOT: /debug/dump-hashes endpoint'i BİLİNÇLİ olarak yoktur → 404. Hash sızdıran yüzey kapatıldı.`

export default function WeakHashingDemo() {
  const [results, setResults] = useState({})
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    const next = {}
    for (const v of ['vulnerable', 'fixed']) {
      next[v] = await proxy(v, MODULE04, SENARYO, 'debug/dump-hashes')
    }
    setResults(next)
    setBusy(false)
  }

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 1 — Weak/Unsalted Hashing + Rainbow Table</h2>
        <div className="meta">CVSS 7.5 (High) · CWE-327 / CWE-759 / CWE-916 · A04:2025</div>
        <p>
          Vulnerable sürüm parolaları tuzsuz MD5 ile saklıyor ve unutulmuş bir debug endpoint'i tüm hash'leri
          sızdırıyor. Fixed sürümde endpoint kaldırılmış (<code>404</code>) ve hash'ler argon2id ile korunuyor.
        </p>
        <div className="note">
          🧪 <b>crack_demo.py (statik açıklama):</b> Bu script bir HTTP endpoint'i değildir, ayrı çalıştırılır.
          Dökülen tuzsuz MD5 hash'lerini küçük bir wordlist ile eşleştirir. Seed parolalarının hepsi kırılır:
          <code>alice=123456</code>, <code>bob=password</code>, <code>carol=qwerty</code>, <code>dave=letmein</code>.
          Tuz olmadığı için önceden hesaplanmış tablo birebir çalışır — argon2id'de (fixed) bu imkânsızdır.
        </div>
      </header>

      <div className="actionbar">
        <button className="btn primary" onClick={run} disabled={busy}>
          Hash'leri Sız (iki sürüme) → GET /debug/dump-hashes
        </button>
      </div>

      <ScenarioBanners
        results={results}
        vulnLeakMsg="Hash'ler açıkta — tuzsuz MD5 çiftleri döküldü, rainbow table ile kırılabilir."
        fixedBlockMsg="Endpoint kaldırılmış (404) — hash'ler argon2id ile korunuyor."
      />
      <CompareGrid results={results} />

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
