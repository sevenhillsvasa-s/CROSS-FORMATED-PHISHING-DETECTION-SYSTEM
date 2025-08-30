!apt update && apt install -y libzbar0
!pip install gradio tldextract whois sentence-transformers transformers beautifulsoup4 pymupdf python-docx pyzbar pillow --quiet

import gradio as gr
import requests, socket, whois, tldextract
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from sentence_transformers import SentenceTransformer, util

from PIL import Image
from pyzbar.pyzbar import decode
from docx import Document
import fitz  # PyMuPDF

# ============================================================
# Project: Phishing URL & Document Scanner
# Author : Sevenhillsvasa S
# License: All Rights Reserved © 2025
# ============================================================

# Load transformer model
model = SentenceTransformer('paraphrase-MiniLM-L6-v2')

# Config
blacklisted_domains = ['serveo.net', 'ngrok.io', 'bit.ly', 'tinyurl.com', 'rb.gy', 'localtunnel.me','trycloudflare.com']
trusted_domains = ['chatgpt.com', 'openai.com', 'google.com', 'colab.research.google.com', 'bing.com', 'microsoft.com', 'github.com']
trusted_text = "Welcome to our official website. Please sign in securely. We value your privacy and security. This is a trusted portal for services, support, and account access."

# --- Utility Functions ---
def get_final_url(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        return response.url
    except:
        return "Error"

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "Unknown"

def get_domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation = domain_info.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        age_days = (datetime.now() - creation).days
        return age_days
    except:
        return -1

def fetch_page_text(url):
    try:
        html = requests.get(url, timeout=5).text
        soup = BeautifulSoup(html, 'html.parser')
        text = soup.get_text()
        return text, html
    except:
        return "", ""

def check_suspicious_html(html):
    score = 0
    suspicious = []
    if "<iframe" in html.lower():
        score += 1
        suspicious.append("Contains iframe")
    if "display:none" in html.lower():
        score += 1
        suspicious.append("Hidden content detected")
    if "eval(" in html.lower() or "unescape(" in html.lower():
        score += 1
        suspicious.append("Obfuscated JavaScript")
    if html.lower().count("script") > 20:
        score += 1
        suspicious.append("Excessive script tags")
    return score, suspicious

def similarity_score(text1, text2):
    emb1 = model.encode(text1, convert_to_tensor=True)
    emb2 = model.encode(text2, convert_to_tensor=True)
    sim = util.cos_sim(emb1, emb2).item()
    return sim

# --- Core Phishing Detection ---
def detect_phishing(input_url):
    try:
        parsed = urlparse(input_url)
        user_domain = parsed.netloc.lower()
        final_url = get_final_url(input_url)
        if final_url == "Error":
            return "❌ Unable to access URL", None

        final_domain = urlparse(final_url).netloc.lower()
        original_ip = get_ip(user_domain)
        final_ip = get_ip(final_domain)
        age_days = get_domain_age(final_domain)
        is_new_domain = age_days != -1 and age_days < 180
        content_text, html = fetch_page_text(final_url)

        if len(content_text.strip()) < 200:
            content_text = html
            similarity = 1.0
        else:
            similarity = similarity_score(content_text[:1000], trusted_text)

        html_score, html_flags = check_suspicious_html(html)

        if any(bad in final_domain for bad in blacklisted_domains):
            verdict = "🔴 PHISHING"
            html_flags.append("🚨 Known tunneling/shortening service used")
            return verdict, {
                "🔗 Final Redirected URL": final_url,
                "🌍 Original vs Final IP": f"{original_ip} ➜ {final_ip}",
                "📆 Domain Age": f"{age_days} days" if age_days != -1 else "Unknown",
                "📜 HTML Red Flags": html_flags,
                "🧠 Semantic Similarity": f"{similarity:.2f}",
                "📝 Notes": ["🚫 Blocked: Uses Serveo/ngrok/tinyurl etc."],
                "🔎 Overall Verdict": verdict
            }

        if any(good in final_domain for good in trusted_domains):
            verdict = "🟢 SAFE"
            return verdict, {
                "🔗 Final Redirected URL": final_url,
                "🌍 Original vs Final IP": f"{original_ip} ➜ {final_ip}",
                "📆 Domain Age": f"{age_days} days" if age_days != -1 else "Unknown",
                "📜 HTML Red Flags": html_flags,
                "🧠 Semantic Similarity": f"{similarity:.2f}",
                "📝 Notes": ["✅ Trusted domain override"],
                "🔎 Overall Verdict": verdict
            }

        risk = 0
        notes = []
        if user_domain != final_domain:
            risk += 1
            notes.append("Domain mismatch on redirection")
        if original_ip != final_ip:
            risk += 1
            notes.append("IP address mismatch")
        if is_new_domain:
            risk += 1
            notes.append("New or unknown domain")
        if html_score > 0:
            risk += html_score
        if similarity < 0.3:
            risk += 2
            html_flags.append("Low semantic similarity to known pages")
        elif similarity < 0.5:
            risk += 1
            html_flags.append("Partial semantic similarity")

        if risk >= 4:
            verdict = "🔴 PHISHING"
        elif risk >= 2:
            verdict = "⚠ SUSPICIOUS"
        else:
            verdict = "🟢 SAFE"

        report = {
            "🔗 Final Redirected URL": final_url,
            "🌍 Original vs Final IP": f"{original_ip} ➜ {final_ip}",
            "📆 Domain Age": f"{age_days} days" if age_days != -1 else "Unknown",
            "📜 HTML Red Flags": html_flags,
            "🧠 Semantic Similarity": f"{similarity:.2f}",
            "📝 Notes": notes,
            "🔎 Overall Verdict": verdict
        }

        return verdict, report
    except Exception as e:
        return "❌ Error", {"Error": str(e)}

# --- File Extractors ---
def extract_links_from_pdf(file_path):
    links = set()
    try:
        doc = fitz.open(file_path)
        for page in doc:
            for link in page.get_links():
                if link.get("uri"):
                    links.add(link["uri"])
        return list(links)
    except Exception as e:
        return [f"Error in PDF: {str(e)}"]

def extract_links_from_docx(file_path):
    links = set()
    try:
        doc = Document(file_path)
        for para in doc.paragraphs:
            if 'http' in para.text:
                for word in para.text.split():
                    if word.startswith("http"):
                        links.add(word)
        return list(links)
    except Exception as e:
        return [f"Error in DOCX: {str(e)}"]

def extract_qr_from_image(image_path):
    try:
        img = Image.open(image_path)
        decoded = decode(img)
        return [obj.data.decode('utf-8') for obj in decoded if obj.data.decode('utf-8').startswith("http")]
    except Exception as e:
        return [f"Error in Image: {str(e)}"]

# --- Gradio Interfaces ---
def url_interface(url):
    verdict, report = detect_phishing(url)
    result = f"### Verdict: {verdict}\n\n"
    if report:
        for k, v in report.items():
            result += f"- {k}: **{v}**\n"
    return result

def file_interface(file):
    path = file.name
    if path.endswith(".pdf"):
        urls = extract_links_from_pdf(path)
    elif path.endswith(".docx"):
        urls = extract_links_from_docx(path)
    elif path.lower().endswith((".png", ".jpg", ".jpeg")):
        urls = extract_qr_from_image(path)
    else:
        return "❌ Unsupported file type."

    if not urls:
        return "⚠ No URLs found."

    result = ""
    for url in urls:
        verdict, report = detect_phishing(url)
        result += f"### ✅ URL: {url}\n**Verdict: {verdict}**\n"
        if report:
            for k, v in report.items():
                result += f"- {k}: **{v}**\n"
        result += "\n---\n"
    return result

# --- Final Gradio App with Author Watermark ---
with gr.Blocks() as demo:
    gr.Markdown("## 🛡 Phishing Scanner")
    gr.Markdown("**Developed by: Sevenhillsvasa S | All Rights Reserved © 2025**")

    with gr.Tab("🔗 URL Scanner"):
        gr.Interface(
            fn=url_interface,
            inputs=gr.Text(label="Enter URL"),
            outputs=gr.Markdown(label="📋 Phishing Report")
        )

    with gr.Tab("📂 File Scanner"):
        gr.Interface(
            fn=file_interface,
            inputs=gr.File(label="Upload PDF / DOCX / Image (QR)"),
            outputs=gr.Markdown(label="📋 Phishing Report from File")
        )

demo.launch(debug=True)
