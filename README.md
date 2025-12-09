# 🛡️ RecTool - AI-Powered Web Penetration Testing Framework

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-lightgrey?style=for-the-badge&logo=linux)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![AI](https://img.shields.io/badge/AI-Gemini%20Pro-orange?style=for-the-badge&logo=google)

**RecTool** is a next-generation, automated penetration testing framework designed for the **DEPI Graduation Project**. Unlike traditional wrappers, RecTool combines industry-standard tools with **custom-built, multi-threaded Python scanners** and integrates **Generative AI** to analyze findings and suggest code fixes.

> **Feature:** The tool automatically checks for dependencies, manages API keys, and auto-installs missing tools on the first run. 🚀

---

## ⚡ Key Features & Workflow

The tool follows an intelligent pipeline to ensure maximum coverage with zero false positives:

1.  **🔍 Deep Reconnaissance & Asset Discovery:**
    * Uses **Amass**, **Assetfinder**, and **Subfinder** for subdomain enumeration.
    * Smart deduplication logic to generate a clean `Finalsubs.txt`.
2.  **🕷️ Intelligent Crawling:**
    * Crawls the main domain and subdomains using **Hakrawler**.
    * **Auto-Filter:** Extracts interesting parameters (`id=`, `file=`, `page=`) for fuzzing.
    * Downloads `.js`, `.php`, and `.json` files for secret harvesting.
3.  **💉 Custom Vulnerability Scanning Engines:**
    * **LFI Scanner (Custom Built):** A multi-threaded Python engine that fuzzes parameters with advanced payloads (Bypass techniques, Null Bytes, Wrappers) to detect Local File Inclusion.
    * **SSRF Scanner (Custom Built):** Detects internal service calls, Cloud Metadata leaks (AWS/GCP), and local port scanning.
    * **SQL Injection:** Automated testing using **SQLMap**.
    * **XSS:** Fast scanning using **Dalfox**.
    * **Nuclei Integration:** Used for template-based scanning of other vulnerability classes.
4.  **🧠 AI-Powered Analysis (The Brain):**
    * Integrates with **Google Gemini AI**.
    * Analyzes the final JSON report.
    * **Generates Fixes:** Writes actual secure code patches (PHP/Python) for developers to fix the found vulnerabilities.
5.  **🕵️ CMS & Exploit Mapping:**
    * Fingerprints technologies using **WhatWeb**.
    * Maps versions to **ExploitDB** to find public CVEs locally.
6.  **📢 Real-time Notifications:**
    * Sends live alerts to your **Telegram Bot**.

---

## 🛠️ Tools & Engines

RecTool uses a hybrid approach of open-source tools and custom engines:

| Category | Engines / Tools |
| :--- | :--- |
| **Reconnaissance** | `Amass`, `Subfinder`, `Assetfinder` |
| **Custom Scanners** | **`LFI_Scanner`**, **`SSRF_Scanner`** (Multi-threaded Python Modules) |
| **Standard Scanners** | `SQLMap`, `Dalfox`, `Nuclei`, `Nikto` |
| **AI Analysis** | **`Google Gemini API`** (Generative AI) |
| **Crawling** | `Hakrawler`, `Katana`|
| **Utils** | `Wget`, `Python Subprocess`, `Urllib` |

---

## ⚙️ Configuration (.env Setup)

To enable **AI Analysis** and **Telegram Notifications**, you must configure your environment variables.

1.  Create a file named `.env` in the root directory.
2.  Add your keys in the following format:

```env
# --- Telegram Alerts ---
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# --- AI Configuration (Required for Smart Report) ---
GEMINI_API_KEY=your_google_gemini_key
GORQ_API_KEY=your_gorq_key
# --- Recon APIs (Optional but Recommended) ---
SHODAN_API_KEY=your_shodan_key
SECURITYTRAILS_API_KEY=your_key
GITHUB_TOKEN=your_toke
```

## 📥 Installation



You don't need to manually install the external tools. **RecTool handles the setup for you!**



```bash

# 1. Clone the repository

git clone https://github.com/JeromeMina191/RecTool.git


# 2. Navigate to the directory

cd RecTool


# 3. Install Python requirements

pip3 install -r requirements.txt --break-system-packages


# 4. Run the tool (Use sudo for full permissions)

sudo python3 RecTool.py
