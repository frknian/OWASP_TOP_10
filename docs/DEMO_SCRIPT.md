# Screencast Demo Script / Ekran Videosu Anlatım Senaryosu

This document provides a structured 2-3 minute script for presenting the OWASP Top 10 Lab. The example uses the IDOR scenario to demonstrate the vulnerable and fixed versions.

Bu doküman, OWASP Top 10 Lab projesinin sunumu için 2-3 dakikalık yapılandırılmış bir ekran videosu akışı ve seslendirme metni sunmaktadır. Örnek senaryo olarak IDOR zafiyeti seçilmiştir.

---

## Script Walkthrough / Video Akışı

| Time / Süre | Visual Action / Görsel Eylem | Spoken Text (Turkish) / Seslendirme Metni |
|---|---|---|
| **0:00 - 0:20** | Show the project homepage / control panel launcher in the browser (`http://127.0.0.1:9000/app/`). Scroll through the 10 modules. | "Merhaba, bu videoda geliştirdiğim OWASP Top 10:2025 Lab projesini tanıtacağım. Proje, en kritik 10 web güvenlik zafiyetini interaktif ve çalıştırılabilir bir lab ortamında inceliyor. Toplam 10 modül altında 34 senaryo bulunuyor." |
| **0:20 - 0:45** | Click on "Technical Launcher" (`/launcher`), locate Module 01 (Broken Access Control) - Scenario 01 (IDOR), and click **Start** on the **Vulnerable** instance. | "Zafiyetleri test etmek için projedeki FastAPI tabanlı Control Panel'i kullanıyoruz. Buradan ilk modülümüz olan IDOR senaryosunun vulnerable (zafiyetli) versiyonunu tek tıkla 8000 portunda başlatıyorum." |
| **0:45 - 1:15** | Open the interactive lab page for IDOR. Perform login as `alice`, then change the account ID in the request from `1` to `2` to view `bob`'s account details. Show the compromised response. | "Lab arayüzünde Alice olarak oturum açıyorum. Kendi verilerimi gördükten sonra, URL parametresindeki ID değerini 1 yerine 2 yapıyorum. Sunucu yetki kontrolü yapmadığı için Bob kullanıcısının hassas verilerine (bakiye ve telefon) doğrudan erişebiliyorum." |
| **1:15 - 1:40** | Go back to the launcher, stop the vulnerable server, and start the **Fixed** version on port 8001. Attempt the same attack (Alice requesting ID 2). Show the `403 Forbidden` response. | "Şimdi zafiyetli sürümü durdurup, fixed (düzeltilmiş) sürümü 8001 portunda başlatıyorum. Aynı isteği Alice oturumuyla Bob'un ID'si olan 2 için tekrar gönderdiğimde, sistem bu kez isteği 403 yetkisiz erişim hatasıyla engelliyor." |
| **1:40 - 2:10** | Open the corresponding `report.md` file in vscode or browser (under `modules/01-broken-access-control/01-idor-horizontal-privilege-escalation/report.md`). Scroll through CVSS, ASVS, and Remediation sections. | "Her zafiyet için hazırladığım profesyonel pentest raporunu açıyorum. Burada zafiyetin CVSS 3.1 skoru, CWE kodu, OWASP ASVS standart eşlemesi ve güvenli kodlama için düzeltme önerileri detaylı şekilde yer alıyor." |
| **2:10 - 2:30** | Show the project directory structure, mock evidence folders, and the automated tests. Run `pytest` command in the terminal showing all tests passing. | "Proje ayrıca GitHub Actions CI sistemiyle otomatik olarak test ediliyor. Pytest ile yazdığım entegrasyon testleri sayesinde tüm bu zafiyet ve savunma davranışları otomatik olarak doğrulanabiliyor. Dinlediğiniz için teşekkürler." |
