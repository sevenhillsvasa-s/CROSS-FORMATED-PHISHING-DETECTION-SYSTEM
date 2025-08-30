# CROSS-FORMATED-PHISHING-DETECTION-SYSTEM
A phishing detection system with Gradio UI. Supports URL scanning, file scanning (PDF, DOCX, QR from image).

# 🛡️ Phishing Detector with Gradio
A phishing detection system built in **Google Colab** using **Python** and **Gradio**.  
It detects phishing by analyzing:
- 🔗 URLs  
- 📂 Links inside PDF / DOCX files  
- 🖼 QR codes from images  

and classifies them as 🟢 SAFE, ⚠ SUSPICIOUS, or 🔴 PHISHING.

---

## 🚀 Features
- ✅ URL scanner with WHOIS lookup & domain age check
- ✅ Detects suspicious HTML patterns (iframes, hidden content, obfuscated JS)
- ✅ AI-powered semantic similarity (SentenceTransformer MiniLM)
- ✅ File scanner for:
  - PDF (extracts embedded links)
  - DOCX (extracts links from text)
  - Images (extracts QR code links)
- ✅ Simple **Gradio interface** with tabs (URL & File scanner)

---

