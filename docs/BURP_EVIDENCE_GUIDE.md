# Burp Suite Evidence Capture Guide / Burp Suite Kanıt Yakalama Rehberi

This document outlines the standard process for capturing, masking, naming, and saving Burp Suite evidence for the 34 web security scenarios in this lab.

Bu doküman, bu laboratuvardaki 34 güvenlik senaryosu için Burp Suite kanıtlarının nasıl yakalanacağını, maskeleneceğini, isimlendirileceğini ve kaydedileceğini açıklamaktadır.

---

## 1. Setup / Kurulum

### Burp Suite Community Edition
1. Download and install Burp Suite Community Edition: https://portswigger.net/burp/communitydownload
2. Start Burp Suite and select a temporary project with default settings.

### Browser Proxy Configuration / Tarayıcı Proxy Ayarları
* **Built-in Browser:** The easiest way is to use Burp's built-in browser (Proxy -> Intercept -> Open Browser). This requires zero system proxy configuration.
* **External Browser:** Configure your browser proxy to point to `127.0.0.1:8080`.
* **Local HTTPS Note:** Since all applications in this lab run on local HTTP (`http://127.0.0.1:XXXX`), installing a custom Burp root CA certificate is **not required**.

---

## 2. Capturing Traffic / Trafik Yakalama

1. Open the Control Panel (launcher) at `http://127.0.0.1:9000/`.
2. Start the desired scenario and navigate to its endpoint.
3. In Burp Suite, go to **Proxy -> HTTP history** to see all requests.
4. Right-click the target request (e.g., login or API access) and select **Send to Repeater** (or press `Ctrl+R` / `Cmd+R`).
5. Go to the **Repeater** tab, modify parameters as required for the attack, and click **Send**.

---

## 3. Evidence Folder Structure / Kanıt Klasör Yapısı

Each scenario has an `evidence/` directory containing a local `README.md` and placeholder files:

```text
modules/<category>/<scenario>/evidence/
├── README.md                  # Scenario-specific instructions
├── 01-authentication-request.png
├── 02-vulnerable-request.png
├── 03-vulnerable-response.png
├── 04-fixed-request.png
└── 05-fixed-response.png
```

* **Do not commit blank PNGs.** Only save actual PNG screenshots when captured. Until then, the `.gitkeep` file keeps the directory tracked.

---

## 4. Screenshot Naming and Masking / Ekran Görüntüsü İsimlendirme ve Maskeleme

### Naming Standards / İsimlendirme Standartları
* `01-authentication-request.png`: Capture of the login/auth request if authentication is required.
* `02-vulnerable-request.png`: Capture of the exploit payload request sent to the `vulnerable` version.
* `03-vulnerable-response.png`: Capture of the successful exploit response from the `vulnerable` version.
* `04-fixed-request.png`: Capture of the exploit payload request sent to the `fixed` version.
* `05-fixed-response.png`: Capture of the blocked/remediated response from the `fixed` version.

### Data Masking / Maskeleme Kuralları
Before saving any screenshot, use an image editor to blur or black out:
* Personal identifiable information (PII) that is not part of the seed database.
* Authorization tokens/cookies if they belong to real production environments (not applicable here, but good practice).
* Keep the port numbers (e.g. `8000` vs `8001`) visible, as they prove which variant was tested!

---

## 5. Embedding in Reports / Raporlara Ekleme

To embed these captures in the scenario's `report.md`, use the following markdown structure:

```markdown
### Burp Suite Proof of Concept

#### Vulnerable Implementation
Here is the vulnerable request showing the attack payload:
![Vulnerable Request](evidence/02-vulnerable-request.png)

And the corresponding response returning the compromised data:
![Vulnerable Response](evidence/03-vulnerable-response.png)

#### Fixed Implementation
The same payload sent to the fixed endpoint:
![Fixed Request](evidence/04-fixed-request.png)

The response demonstrating that the attack was successfully blocked or sanitized:
![Fixed Response](evidence/05-fixed-response.png)
```
