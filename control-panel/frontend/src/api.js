// control-panel'in reverse-proxy'sine istek atan basit yardımcı.
// credentials: 'include' → tarayıcı, proxy'nin variant-özel Path'e sabitlediği
// session cookie'lerini isteğe dahil eder (vulnerable/fixed cookie'leri çakışmaz).
export async function proxy(variant, modul, senaryo, path, { method = 'GET', body, form, headers = {} } = {}) {
  const url = `/api/proxy/${variant}/${modul}/${senaryo}/${path}`
  const opts = { method, credentials: 'include', headers: { ...headers } }
  if (form !== undefined) {
    // application/x-www-form-urlencoded — FastAPI'de Form(...) alan endpoint'ler için.
    opts.headers['Content-Type'] = 'application/x-www-form-urlencoded'
    opts.body = new URLSearchParams(form).toString()
  } else if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json'
    opts.body = JSON.stringify(body)
  }
  const res = await fetch(url, opts)
  const text = await res.text()
  let data
  try {
    data = JSON.parse(text)
  } catch {
    data = text
  }
  return { status: res.status, ok: res.ok, data }
}

// Bir senaryo backend'ini başlatır (idempotent — zaten çalışıyorsa "already_running").
// SRI gibi bazı senaryolar iframe'i DOĞRUDAN backend portundan yükler (proxy'den değil),
// bu yüzden backend'in çalıştığından emin olmak için önce bunu çağırırız. Dönen port,
// iframe src'sinde kullanılır.
export async function startBackend(variant, modul, senaryo) {
  const res = await fetch(`/api/start/${variant}/${modul}/${senaryo}`, { method: 'POST' })
  const data = await res.json().catch(() => ({}))
  return { ok: res.ok, port: data.port, status: data.status, error: data.error }
}

export const MODULE01 = '01-broken-access-control'
export const MODULE02 = '02-security-misconfiguration'
export const MODULE03 = '03-software-supply-chain-failures'
export const MODULE04 = '04-cryptographic-failures'
export const MODULE05 = '05-injection'
export const MODULE06 = '06-insecure-design'
export const MODULE07 = '07-authentication-failures'
export const MODULE08 = '08-software-data-integrity-failures'
export const MODULE09 = '09-security-logging-alerting-failures'
export const MODULE10 = '10-mishandling-exceptional-conditions'
