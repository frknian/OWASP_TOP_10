import { useState } from 'react'
import './Landing.css'

// ---------------------------------------------------------------------------
// GERÇEK modül verisi — README.md "Modül Listesi (OWASP Top 10:2025)" tablosu,
// INTRODUCTION.md kategori özetleri ve her modülün report.md "Bu Kategori Nedir?"
// bloklarından derlenmiştir. Tasarım mockup'ındaki sahte kod / sahte
// "exploit_çalıştır()" terminali burada YER ALMAZ: gerçek saldırı demoları her
// senaryonun kendi lab sayfasındadır; bu sayfa yalnızca gerçek özet + gezinme.
//
// Sıralama App.jsx'teki GROUPS ile birebir aynıdır: senaryo listesi, senaryo
// sayısı ve ilk senaryonun id'si `groups` prop'undan alınır (tek doğruluk
// kaynağı orasıdır — bu dosya yalnızca kategori düzeyindeki metadatayı tutar).
// ---------------------------------------------------------------------------
const MODULES = [
  {
    code: 'A01',
    kebab: 'broken-access-control',
    title: 'Broken Access Control',
    change: 'A01 → A01 · listenin zirvesinde kaldı; SSRF bu başlığa konsolide edildi',
    desc: 'Kullanıcının yetkisi olmayan kaynaklara/işlemlere erişebilmesi: başka bir kullanıcının kaydını görmek (IDOR/BOLA), yönetici fonksiyonunu çağırmak (BFLA) veya erişim kontrolünün yalnızca istemci tarafında zorlanması. 2025 sürümünde SSRF de bu kategoriye dahil edildi.',
    cwes: ['CWE-639', 'CWE-285', 'CWE-602'],
  },
  {
    code: 'A02',
    kebab: 'security-misconfiguration',
    title: 'Security Misconfiguration',
    change: 'A05 → A02 · yükseldi',
    desc: 'Kod hatası değil, ayar hatası: unutulmuş kurulum/örnek uygulamalar, varsayılan parolalar, açık dizin listeleme, aşırı detaylı hata mesajları ve yanlış izinli bulut depolama.',
    cwes: ['CWE-1392', 'CWE-548', 'CWE-209', 'CWE-732'],
  },
  {
    code: 'A03',
    kebab: 'software-supply-chain-failures',
    title: 'Software Supply Chain Failures',
    change: 'A06 → A03 · yükseldi ve genişledi (eski: Vulnerable and Outdated Components)',
    desc: 'Kendi kodun güvenli olsa bile bağımlılıkların (kütüphane, paket, build aracı) güvenli olmayabilir. Log4Shell, Bybit tarzı koşullu backdoor’lar ve npm worm’ları bu sınıftandır. Bu modüldeki senaryolar DEFANGED simülasyondur.',
    cwes: ['CWE-1395', 'CWE-506', 'CWE-477'],
  },
  {
    code: 'A04',
    kebab: 'cryptographic-failures',
    title: 'Cryptographic Failures',
    change: 'A02 → A04 · düştü',
    desc: 'Hassas verinin yetersiz kriptografik koruması: zayıf/tuzsuz parola hashing’i (rainbow table), kaynak koda gömülü şifreleme anahtarları ve şifrelenmemiş hassas veri depolama.',
    cwes: ['CWE-759', 'CWE-916', 'CWE-321', 'CWE-311'],
  },
  {
    code: 'A05',
    kebab: 'injection',
    title: 'Injection',
    change: 'A03 → A05 · düştü; XSS bu kategoride',
    desc: 'Kullanıcı girdisinin veri yerine kod olarak yorumlanması: string birleştirmeli ve ORM üzerinden SQL injection, OS komut enjeksiyonu (DEFANGED) ve reflected XSS.',
    cwes: ['CWE-89', 'CWE-78', 'CWE-79'],
  },
  {
    code: 'A06',
    kebab: 'insecure-design',
    title: 'Insecure Design',
    change: 'A04 → A06 · düştü',
    desc: 'Kod hatası değil, tasarım eksikliği: güvensiz parola kurtarma soruları, iş mantığı bypass’ı ve bot/rate-limiting eksikliği. Düzeltme bir satır kod değil, akışın/iş kuralının yeniden tasarlanmasıdır.',
    cwes: ['CWE-640', 'CWE-841', 'CWE-770', 'CWE-799'],
  },
  {
    code: 'A07',
    kebab: 'authentication-failures',
    title: 'Authentication Failures',
    change: 'A07 → A07 · sıra değişmedi',
    desc: 'Kimlik doğrulama ve oturum yönetimi zayıflıkları: brute-force/credential-stuffing koruması yokluğu, MFA eksikliği ve bozuk session timeout/logout yaşam döngüsü.',
    cwes: ['CWE-307', 'CWE-308', 'CWE-613'],
  },
  {
    code: 'A08',
    kebab: 'software-or-data-integrity-failures',
    title: 'Software or Data Integrity Failures',
    change: 'A08 → A08 · sıra değişmedi',
    desc: 'Yazılımın veya verinin kaynağına/bütünlüğüne doğrulama yapmadan güvenmek: güvensiz deserialization (DEFANGED), mass assignment ve SRI olmadan üçüncü taraf script yükleme.',
    cwes: ['CWE-502', 'CWE-915', 'CWE-829'],
  },
  {
    code: 'A09',
    kebab: 'security-logging-and-alerting-failures',
    title: 'Security Logging and Alerting Failures',
    change: 'A09 → A09 · isim değişti: Monitoring → Alerting',
    desc: 'Saldırı fark edilmezse sonsuza kadar sürebilir: loglara hassas veri yazılması, log injection/forging ve “log var ama kimse tepki vermiyor” (alerting eşiği yokluğu).',
    cwes: ['CWE-532', 'CWE-117', 'CWE-778'],
  },
  {
    code: 'A10',
    kebab: 'mishandling-of-exceptional-conditions',
    title: 'Mishandling of Exceptional Conditions',
    change: 'YENİ · eski A10 (SSRF) A01’e taşındığı için bu sıra boşaldı',
    desc: '2025’in yepyeni kategorisi: uygulamanın beklenmedik durumlarla (hata, timeout, kaynak tükenmesi) nasıl başa çıktığı. Kalbinde “fail open vs fail secure” ayrımı vardır.',
    cwes: ['CWE-404', 'CWE-636', 'CWE-209', 'CWE-460'],
  },
]

export default function Landing({ groups, onEnter }) {
  const [sel, setSel] = useState(0) // seçili kategori (varsayılan: A01)
  const mod = MODULES[sel]
  const items = groups[sel]?.items ?? []
  const firstId = items[0]?.id

  return (
    <div className="landing">
      {/* 1 — Header */}
      <header className="l-header">
        <div className="l-logo">
          OWASP_TOP10 <span>// interaktif lab</span>
        </div>
        <div className="l-header-right">127.0.0.1 · local only</div>
      </header>

      {/* 2 — Hero: sol başlık + CTA, sağ terminal kartı */}
      <section className="l-hero">
        <div className="l-hero-left">
          <div className="l-tag">// web güvenliği eğitim laboratuvarı</div>
          <h1 className="l-title">
            OWASP TOP 10
            <br />
            <span className="l-amber">
              :2025<span className="l-cursor">_</span>
            </span>
          </h1>
          <p className="l-lead">
            2025 listesindeki 10 risk kategorisini, bilinçli zafiyetli yazılmış mini web
            uygulamaları üzerinde gösteren interaktif lab. 34 senaryonun her biri;
            çalıştırılabilir <b className="l-red">vulnerable</b> /{' '}
            <b className="l-green">fixed</b> sürüm çifti, CVSS 3.1 · CWE · ASVS eşlemeli
            pentest raporu ve tek tıkla saldırı demosu içerir — tamamı yalnızca kendi
            makinende, 127.0.0.1 üzerinde çalışır.
          </p>
          <button className="l-cta" onClick={() => onEnter()}>
            laboratuvara gir ↓
          </button>
        </div>

        <div className="l-terminal" aria-hidden="true">
          <div className="l-term-head">
            <i className="r" />
            <i className="y" />
            <i className="g" />
            <span>scan — zsh</span>
          </div>
          <div className="l-term-body">
            <div className="l-cmd">$ ./scan --standard owasp:2025</div>
            <div className="l-term-sub">10 kategori taranıyor…</div>
            {MODULES.map((m, i) => (
              <div className="l-term-line" key={m.code}>
                <span className="l-dot" />
                <span className="l-term-code">{m.code}</span>
                <span className="l-term-name">{m.kebab}</span>
                <span className="l-term-count">
                  {groups[i]?.items.length ?? 0} senaryo
                </span>
              </div>
            ))}
            <div className="l-term-done">
              ✓ 10/10 modül · 34 senaryo · vulnerable+fixed hazır
            </div>
          </div>
        </div>
      </section>

      {/* 3 — İstatistik rozetleri */}
      <div className="l-stats">
        <span className="l-chip">
          <b>10</b> risk
        </span>
        <span className="l-chip">
          <b>2</b> yeni kategori · A03 + A10
        </span>
        <span className="l-chip">SSRF birleşti → A01</span>
        <span className="l-chip">A02 ↑ #5 → #2</span>
      </div>

      {/* 4 — On riski keşfet: sol liste, sağ GERÇEK detay paneli */}
      <section className="l-explore">
        <div className="l-tag">// on riski keşfet</div>
        <h2 className="l-h2">
          2025 listesi <span className="l-amber">— kategoriye tıkla, gerçek özeti gör</span>
        </h2>
        <div className="l-explore-grid">
          <div className="l-list" role="tablist" aria-label="OWASP Top 10:2025 kategorileri">
            {MODULES.map((m, i) => (
              <button
                key={m.code}
                role="tab"
                aria-selected={sel === i}
                className={sel === i ? 'l-row active' : 'l-row'}
                onClick={() => setSel(i)}
              >
                <span className="l-row-code">{m.code}</span>
                <span className="l-row-title">{m.title}</span>
                <span className="l-row-count">{groups[i]?.items.length ?? 0}</span>
              </button>
            ))}
          </div>

          <div className="l-detail" role="tabpanel">
            <div className="l-detail-head">
              <span className="l-code-badge">{mod.code}</span>
              <div>
                <h3>{mod.title}</h3>
                <div className="l-change">{mod.change}</div>
              </div>
            </div>
            <p className="l-desc">{mod.desc}</p>
            <div className="l-cwes">
              {mod.cwes.map((c) => (
                <span className="l-cwe" key={c}>
                  {c}
                </span>
              ))}
            </div>
            <div className="l-scen-head">// senaryolar</div>
            <div className="l-scen-list">
              {items.map((it) => (
                <div className="l-scen" key={it.id}>
                  <span className="l-dot amber" />
                  {it.label}
                </div>
              ))}
            </div>
            <div className="l-detail-foot">
              <span className="l-foot-note">
                {items.length} senaryo · her biri vulnerable + fixed
              </span>
              <button className="l-cta ghost" onClick={() => onEnter(firstId)}>
                bu modülü incele →
              </button>
            </div>
          </div>
        </div>
      </section>

      <footer className="l-footer">
        <span>
          tüm senaryolar yalnızca 127.0.0.1 üzerinde çalışır · eğitim amaçlı, bilinçli
          zafiyetli uygulamalar
        </span>
        <a href="/launcher">teknik launcher ↗</a>
      </footer>
    </div>
  )
}
