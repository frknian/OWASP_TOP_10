import { useState } from 'react'
import Landing from './Landing.jsx'
import IdorDemo from './scenarios/module01/IdorDemo.jsx'
import BflaDemo from './scenarios/module01/BflaDemo.jsx'
import ClientBypassDemo from './scenarios/module01/ClientBypassDemo.jsx'
import ForgottenSampleAppDemo from './scenarios/module02/ForgottenSampleAppDemo.jsx'
import DirectoryListingDemo from './scenarios/module02/DirectoryListingDemo.jsx'
import VerboseErrorDemo from './scenarios/module02/VerboseErrorDemo.jsx'
import PublicStorageDemo from './scenarios/module02/PublicStorageDemo.jsx'
import Log4ShellDemo from './scenarios/module03/Log4ShellDemo.jsx'
import BackdoorDemo from './scenarios/module03/BackdoorDemo.jsx'
import WormDemo from './scenarios/module03/WormDemo.jsx'
import StrutsRceDemo from './scenarios/module03/StrutsRceDemo.jsx'
import WeakHashingDemo from './scenarios/module04/WeakHashingDemo.jsx'
import HardcodedKeyDemo from './scenarios/module04/HardcodedKeyDemo.jsx'
import PlaintextAtRestDemo from './scenarios/module04/PlaintextAtRestDemo.jsx'
import SqlInjectionDemo from './scenarios/module05/SqlInjectionDemo.jsx'
import OrmInjectionDemo from './scenarios/module05/OrmInjectionDemo.jsx'
import CommandInjectionDemo from './scenarios/module05/CommandInjectionDemo.jsx'
import XssDemo from './scenarios/module05/XssDemo.jsx'
import CredentialRecoveryDemo from './scenarios/module06/CredentialRecoveryDemo.jsx'
import BookingBypassDemo from './scenarios/module06/BookingBypassDemo.jsx'
import RateLimitDemo from './scenarios/module06/RateLimitDemo.jsx'
import CredentialStuffingDemo from './scenarios/module07/CredentialStuffingDemo.jsx'
import MfaDemo from './scenarios/module07/MfaDemo.jsx'
import SessionTimeoutDemo from './scenarios/module07/SessionTimeoutDemo.jsx'
import DeserializationDemo from './scenarios/module08/DeserializationDemo.jsx'
import MassAssignmentDemo from './scenarios/module08/MassAssignmentDemo.jsx'
import SriDemo from './scenarios/module08/SriDemo.jsx'
import SensitiveLogDemo from './scenarios/module09/SensitiveLogDemo.jsx'
import LogInjectionDemo from './scenarios/module09/LogInjectionDemo.jsx'
import AlertingDemo from './scenarios/module09/AlertingDemo.jsx'
import ResourceExhaustionDemo from './scenarios/module10/ResourceExhaustionDemo.jsx'
import FailOpenDemo from './scenarios/module10/FailOpenDemo.jsx'
import DbErrorLeakDemo from './scenarios/module10/DbErrorLeakDemo.jsx'
import RollbackDemo from './scenarios/module10/RollbackDemo.jsx'

const GROUPS = [
  {
    module: 'Modül 01 — Broken Access Control',
    items: [
      { id: 'idor', label: '1 · IDOR / BOLA', comp: IdorDemo },
      { id: 'bfla', label: '2 · Missing Function Level AC', comp: BflaDemo },
      { id: 'bypass', label: '3 · Client-Side Enforcement Bypass', comp: ClientBypassDemo },
    ],
  },
  {
    module: 'Modül 02 — Security Misconfiguration',
    items: [
      { id: 'sample', label: '1 · Forgotten Sample App', comp: ForgottenSampleAppDemo },
      { id: 'listing', label: '2 · Directory Listing', comp: DirectoryListingDemo },
      { id: 'verbose', label: '3 · Verbose Error Messages', comp: VerboseErrorDemo },
      { id: 'storage', label: '4 · Public Cloud Storage', comp: PublicStorageDemo },
    ],
  },
  {
    module: 'Modül 03 — Software Supply Chain Failures',
    items: [
      { id: 'log4shell', label: '1 · Log4Shell tarzı', comp: Log4ShellDemo },
      { id: 'backdoor', label: '2 · Conditional Backdoor', comp: BackdoorDemo },
      { id: 'worm', label: '3 · Post-install Worm', comp: WormDemo },
      { id: 'struts', label: '4 · Component RCE (Struts)', comp: StrutsRceDemo },
    ],
  },
  {
    module: 'Modül 04 — Cryptographic Failures',
    items: [
      { id: 'weakhash', label: '1 · Weak Hashing + Rainbow Table', comp: WeakHashingDemo },
      { id: 'hardkey', label: '2 · Hardcoded Encryption Key', comp: HardcodedKeyDemo },
      { id: 'plaintext', label: '3 · Plaintext Data at Rest', comp: PlaintextAtRestDemo },
    ],
  },
  {
    module: 'Modül 05 — Injection',
    items: [
      { id: 'sqli', label: '1 · SQL Injection', comp: SqlInjectionDemo },
      { id: 'ormi', label: '2 · ORM Injection (Blind Trust)', comp: OrmInjectionDemo },
      { id: 'cmdi', label: '3 · OS Command Injection', comp: CommandInjectionDemo },
      { id: 'xss', label: '4 · Reflected XSS', comp: XssDemo },
    ],
  },
  {
    module: 'Modül 06 — Insecure Design',
    items: [
      { id: 'credrec', label: '1 · Insecure Credential Recovery', comp: CredentialRecoveryDemo },
      { id: 'booking', label: '2 · Business Logic Bypass', comp: BookingBypassDemo },
      { id: 'ratelimit', label: '3 · Missing Rate Limiting', comp: RateLimitDemo },
    ],
  },
  {
    module: 'Modül 07 — Authentication Failures',
    items: [
      { id: 'credstuff', label: '1 · Credential Stuffing', comp: CredentialStuffingDemo },
      { id: 'mfa', label: '2 · MFA Yokluğu', comp: MfaDemo },
      { id: 'sessiontimeout', label: '3 · Session Timeout / Logout', comp: SessionTimeoutDemo },
    ],
  },
  {
    module: 'Modül 08 — Software or Data Integrity Failures',
    items: [
      { id: 'deserialization', label: '1 · Insecure Deserialization', comp: DeserializationDemo },
      { id: 'massassign', label: '2 · Mass Assignment', comp: MassAssignmentDemo },
      { id: 'sri', label: '3 · Missing SRI', comp: SriDemo },
    ],
  },
  {
    module: 'Modül 09 — Security Logging and Alerting Failures',
    items: [
      { id: 'sensitivelog', label: '1 · Loglara Hassas Veri', comp: SensitiveLogDemo },
      { id: 'loginjection', label: '2 · Log Injection / Forging', comp: LogInjectionDemo },
      { id: 'alerting', label: '3 · Alerting Eksikliği', comp: AlertingDemo },
    ],
  },
  {
    module: 'Modül 10 — Mishandling of Exceptional Conditions',
    items: [
      { id: 'resourceexhaustion', label: '1 · Kaynak Tükenmesi (DoS)', comp: ResourceExhaustionDemo },
      { id: 'failopen', label: '2 · Fail-Open Authentication', comp: FailOpenDemo },
      { id: 'dberrorleak', label: '3 · DB Hata Sızıntısı', comp: DbErrorLeakDemo },
      { id: 'rollback', label: '4 · Rollback Eksikliği', comp: RollbackDemo },
    ],
  },
]

const ALL = GROUPS.flatMap((g) => g.items)

export default function App() {
  // view: 'landing' (yeni tanıtım/gezgin sayfası) | 'lab' (sidebar + senaryo demoları)
  const [view, setView] = useState('landing')
  const [active, setActive] = useState('idor')

  // Landing'den giriş: "laboratuvara gir" → varsayılan ilk senaryo;
  // "bu modülü incele →" → ilgili modülün ilk senaryosu (scenarioId) seçili gelir.
  const enterLab = (scenarioId = ALL[0].id) => {
    setActive(scenarioId)
    setView('lab')
  }

  if (view === 'landing') {
    return <Landing groups={GROUPS} onEnter={enterLab} />
  }

  const Active = ALL.find((s) => s.id === active).comp
  return (
    <div className="layout">
      <aside className="sidebar">
        <button className="nav backhome" onClick={() => setView('landing')}>
          ← ana sayfa
        </button>
        <h1>Interactive Lab</h1>
        {GROUPS.map((g) => (
          <div key={g.module} className="navgroup">
            <div className="module-label">{g.module}</div>
            <nav>
              {g.items.map((s) => (
                <button
                  key={s.id}
                  className={active === s.id ? 'nav active' : 'nav'}
                  onClick={() => setActive(s.id)}
                >
                  {s.label}
                </button>
              ))}
            </nav>
          </div>
        ))}
        <div className="hint">
          Backend'ler istek anında otomatik başlatılır; ilk istekte birkaç saniye sürebilir.
        </div>
      </aside>
      <main className="content">
        <Active />
      </main>
    </div>
  )
}
