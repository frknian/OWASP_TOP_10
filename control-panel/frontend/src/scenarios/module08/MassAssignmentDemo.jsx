import { useState } from 'react'
import { proxy, MODULE08 } from '../../api.js'
import { HowItWorks } from '../../ui.jsx'

const SENARYO = '02-mass-assignment'

const STEPS = [
  'Mass assignment: istemciden gelen JSON, hangi alanların yazılabilir olduğu sunucu tarafında kısıtlanmadan doğrudan objeye eşlenir.',
  'Vulnerable model TÜM alanları (role dahil) kabul eder → {"bio":"...","role":"admin"} rolü yükseltir (privilege escalation).',
  'Kök neden bir trust boundary ihlalidir: "istemci hangi alanları değiştirebilir?" kararı istemci girdisine bırakılmıştır.',
  'Fixed: ayrı bir allowlist DTO (ProfileUpdateRequest) yalnızca email + bio tanır; role sözleşmenin dışındadır.',
  'extra="forbid" → sözleşme dışı bir alan (role) gelirse istek 422 ile reddedilir, hiçbir değişiklik yazılmaz.',
]

const VULN_CODE = `class ProfileUpdate(BaseModel):
    username: str | None = None
    email: str | None = None
    bio: str | None = None
    role: str | None = None   # ← ayrıcalık alanı istemci girdisine bağlı

changes = update.model_dump(exclude_unset=True)
user.update(changes)          # gelen ne varsa doğrudan yazılıyor`

const FIXED_CODE = `class ProfileUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")   # sözleşme dışı alan → 422
    email: str | None = None
    bio: str | None = None
    # role BURADA YOK — istemci girdisine hiçbir yolla bağlanamaz

changes = update.model_dump(exclude_unset=True)   # yalnızca email/bio
user.update(changes)`

function roleColor(role) {
  return role === 'admin' ? '#ff9aa0' : '#7CFFB2'
}

function Panel({ title, cls, update, profile }) {
  return (
    <div className={cls}>
      <h3>{title}</h3>
      {!update ? (
        <div className="muted">Henüz istek atılmadı.</div>
      ) : (
        <>
          <div className="statusline">PATCH /profile/update → HTTP {update.status}</div>
          <pre>{typeof update.data === 'string' ? update.data : JSON.stringify(update.data, null, 2)}</pre>
          {profile && (
            <>
              <div className="statusline" style={{ marginTop: 8 }}>
                GET /profile → role:{' '}
                <b style={{ color: roleColor(profile.data?.role) }}>{profile.data?.role}</b>
              </div>
              <pre>{JSON.stringify(profile.data, null, 2)}</pre>
            </>
          )}
        </>
      )}
    </div>
  )
}

export default function MassAssignmentDemo() {
  const [bio, setBio] = useState('Merhaba, ben bir kullanıcıyım')
  const [injectRole, setInjectRole] = useState(true)
  const [vUpd, setVUpd] = useState(null)
  const [fUpd, setFUpd] = useState(null)
  const [vProf, setVProf] = useState(null)
  const [fProf, setFProf] = useState(null)
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    const body = injectRole ? { bio, role: 'admin' } : { bio }
    // Vulnerable
    const vu = await proxy('vulnerable', MODULE08, SENARYO, 'profile/update', { method: 'PATCH', body })
    setVUpd(vu)
    setVProf(await proxy('vulnerable', MODULE08, SENARYO, 'profile'))
    // Fixed
    const fu = await proxy('fixed', MODULE08, SENARYO, 'profile/update', { method: 'PATCH', body })
    setFUpd(fu)
    setFProf(await proxy('fixed', MODULE08, SENARYO, 'profile'))
    setBusy(false)
  }

  const vRole = vProf?.data?.role
  const fUpd422 = fUpd?.status === 422

  return (
    <div>
      <header className="scenario-head">
        <h2>Senaryo 2 — Mass Assignment</h2>
        <div className="meta">CVSS 8.8 (High) · CWE-915 · A08:2025</div>
        <p>
          <code>PATCH /profile/update</code> gelen gövdeyi kısıtlamadan objeye yazar. İstek gövdesine{' '}
          <code>role: admin</code> eklendiğinde vulnerable sürüm rolü yükseltir. Fixed sürüm allowlist DTO
          (<code>extra="forbid"</code>) ile <code>role</code>'ü <code>422</code> ile reddeder.
        </p>
      </header>

      <div className="actionbar">
        <div className="field" style={{ flex: 1, minWidth: 240 }}>
          <label>Bio</label>
          <input value={bio} onChange={(e) => setBio(e.target.value)} style={{ width: '100%' }} />
        </div>
        <label className="field" style={{ flexDirection: 'row', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
          <input type="checkbox" checked={injectRole} onChange={(e) => setInjectRole(e.target.checked)} />
          <span>İstek gövdesine <code>role:admin</code> ekle</span>
        </label>
        <button className="btn primary" onClick={run} disabled={busy}>
          Profili Güncelle (iki sürüme)
        </button>
      </div>

      {vRole && (
        vRole === 'admin' ? (
          <div className="banner leak">🔓 Yetki yükseltildi — vulnerable sürümde role artık <code>admin</code> (privilege escalation).</div>
        ) : (
          <div className="banner neutral">Vulnerable: role = {vRole} (role:admin eklemeyi deneyin).</div>
        )
      )}
      {fUpd && (
        fUpd422 ? (
          <div className="banner safe">🔒 Beklenmeyen alan reddedildi — fixed sürümde <code>role</code> için 422 extra_forbidden, role hâlâ <code>user</code>.</div>
        ) : (
          <div className="banner neutral">Fixed: HTTP {fUpd.status} (yalnızca allowlist alanları — role kapalı).</div>
        )
      )}

      <div className="compare">
        <Panel title="Vulnerable — tüm alanlar bind ediliyor" cls={vRole === 'admin' ? 'panel allowed' : 'panel'} update={vUpd} profile={vProf} />
        <Panel title="Fixed — allowlist DTO" cls={fUpd422 ? 'panel blocked' : 'panel'} update={fUpd} profile={fProf} />
      </div>

      <HowItWorks steps={STEPS} vulnCode={VULN_CODE} fixedCode={FIXED_CODE} />
    </div>
  )
}
