# 🛡️ RecTool - Automated Web Penetration Testing Framework

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-lightgrey?style=for-the-badge&logo=linux)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**RecTool** is a comprehensive, automated penetration testing framework designed for the **DEPI Graduation Project**. It orchestrates powerful open-source security tools to perform reconnaissance, vulnerability scanning, CMS fingerprinting, and exploit detection—all in one workflow.

> **Feature:** The tool automatically checks for required dependencies (Go tools, Python libraries, System packages) and installs them upon the first run. 🚀

---

## ⚡ Features & Workflow

The tool follows a strict, logical pipeline to ensure maximum coverage:

1.  **🔍 Deep Reconnaissance (Subdomain Enumeration):**
    * Uses **Amass**, **Assetfinder**, and **Subfinder**.
    * Merges results and removes duplicates to create a clean `Finalsubs.txt`.
2.  **🕷️ Crawling & Extraction:**
    * Crawls the main domain and all discovered subdomains using **Hakrawler**.
    * **Auto-Filter & Download:** Automatically filters and downloads interesting files (`.js`, `.php`, `.json`) for offline analysis.
    * Extracts URLs with parameters for fuzzing.
3.  **💉 Vulnerability Scanning:**
    * **SQL Injection:** Automated testing using **SQLMap** (Payload injection & DB enumeration).
    * **XSS:** Fast and accurate scanning using **Dalfox**.
    * **LFI & SSRF:** Advanced detection using **Nuclei** (Template-based scanning for maximum accuracy).
    * **Info Disclosure:** Server analysis using **Nikto**.
4.  **🕵️ CMS & Exploit Analysis:**
    * Fingerprints technologies using **WhatWeb**.
    * Maps detected versions to **ExploitDB (SearchSploit)** to find CVEs and public exploits locally.
5.  **📢 Notifications:**
    * Real-time alerts sent directly to your **Telegram Bot** ([@RecToolvot](https://t.me/RecToolvot)).
6.  **📊 Reporting:**
    * Generates a final **JSON Report** summarizing all findings.

---

## 🛠️ Tools Integrated

RecTool automates the following industry-standard tools:

| Category | Tools Used |
| :--- | :--- |
| **Reconnaissance** | `Amass`, `Subfinder`, `Assetfinder` |
| **Crawling** | `Hakrawler` |
| **Scanning** | `SQLMap`, `Dalfox`, `Nuclei`, `Nikto` |
| **CMS / Exploits** | `WhatWeb`, `SearchSploit (ExploitDB)` |
| **Utils** | `Wget`, `Python Subprocess` |

---

## 📥 Installation

You don't need to manually install the external tools. **RecTool handles the setup for you!**

```bash
# 1. Clone the repository
git clone [https://github.com/JeromeMina191/RecTool.git](https://github.com/JeromeMina191/RecTool.git)

# 2. Navigate to the directory
cd RecTool

# 3. Install Python requirements
pip3 install -r requirements.txt

# 4. Run the tool (Use sudo for full permissions)
sudo python3 RecTool.py
