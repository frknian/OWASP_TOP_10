# Screencast Recording and GIF Generation Guide / Kayıt ve GIF Üretim Rehberi

This document provides instructions on how to record a high-quality screencast demo on macOS and convert it into an optimized GIF for the GitHub repository.

Bu doküman, macOS üzerinde yüksek kaliteli bir ekran kaydı alma ve bu kaydı GitHub reposunda sergilenmek üzere optimize edilmiş bir GIF dosyasına dönüştürme adımlarını içerir.

---

## 1. Recording Setup / Ekran Kayıt Hazırlığı

### Tools / Araçlar
* **QuickTime Player:** Built-in macOS tool (e.g. `Cmd + Shift + 5` to select screen region and record).
* **OBS Studio (Optional):** If you need advanced layout/audio settings.

### Resolution & Aspect Ratio / Çözünürlük ve Sınırlar
* **Viewport Size:** Resize your browser window to a standard resolution (e.g. `1280x720` or `1920x1080`). Do not record your entire widescreen monitor, as details will become too small to read on GitHub.
* **Font Sizing:** Increase font size in vscode / terminal (`Cmd +` in vscode) to ensure code snippets are easily readable on mobile devices.
* **Hide Clutter:** Close unused browser tabs, bookmarks bar, and clear your desktop/terminal history.

---

## 2. Recording Flow / Kayıt Adımları

Following the [DEMO_SCRIPT.md](DEMO_SCRIPT.md):
1. Start the control panel launcher:
   ```bash
   python3 -m venv venv
   ./venv/bin/pip install -r requirements.txt
   ./venv/bin/uvicorn main:app --host 127.0.0.1 --port 9000
   ```
2. Open `http://127.0.0.1:9000` in the browser.
3. Start the recording.
4. Execute the IDOR vulnerable attack and fixed blocking behavior.
5. Show the vscode code/reports and run the tests:
   ```bash
   PYTHONPATH=. pytest -m "not slow and not browser"
   ```
6. Stop the recording. Save the output as `owasp-lab-demo.mp4`.

---

## 3. GIF Generation / MP4'ten GIF Üretme

To display a smooth preview animation on the GitHub landing page, convert a short (~10-15s) clip of the recording to a GIF.

### Prerequisite / Önkoşul
Ensure `ffmpeg` is installed:
```bash
brew install ffmpeg
```

### Conversion Command / Çevrim Komutu
Run the following command to generate a highly optimized, high-fidelity GIF:

```bash
ffmpeg -i owasp-lab-demo.mp4 -vf "fps=10,scale=1000:-1:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse" assets/demo/owasp-lab-preview.gif
```

* **Command breakdown:**
  * `fps=10`: Sets frame rate to 10 frames per second (reduces file size while keeping motion smooth).
  * `scale=1000:-1`: Resizes width to 1000 pixels while maintaining aspect ratio.
  * `flags=lanczos`: Uses lanczos scaling algorithm for high quality.
  * `palettegen` and `paletteuse`: Generates a custom 256-color palette based on the video content, avoiding color banding and artifacts.

### Repository Paths / Depo Yolları
Save the files under these locations when generated:
* `assets/demo/owasp-lab-demo.mp4`
* `assets/demo/owasp-lab-preview.gif`
