from datetime import datetime
import subprocess
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
    input_file=place+"/finalRawlers.txt"
    output_file=place+"/Parameters.txt"
    print(f"[+] Filtering URLs with parameters from {input_file}...")
    ignored_extensions = (".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".svg")
    count = 0
    try:
        with open(input_file, 'r') as f_in, open(output_file, 'a') as f_out:
            for line in f_in:
                url = line.strip()
                if "?" in url and "=" in url:
                    if not url.lower().endswith(ignored_extensions):
                        f_out.write(url + "\n")
                        count += 1
        print(colored(f"[+] Done! Found {count} parameter URLs. Saved to {output_file}","cyan") )
        subprocess.run(f"chmod -R 777 {output_file}", shell=True)
    except FileNotFoundError:
        print(colored(f"[-] Error: File {input_file} not found!","red") )
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
                if line.strip().startswith("Target:") or line.strip().startswith("[VULN CHECK]"):
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
            lfi=get_file_length(place + "/lfi.txt")
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
############    LFI      ##############
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

def check_single_payload(target_url, payload, success_indicators):
    full_url = f"{target_url}{payload}"
    try:
        # Timeout سريع جداً (ثانيتين)
        response = requests.get(full_url, timeout=2)

        for indicator in success_indicators:
            if indicator in response.text:
                return (full_url, payload, indicator)  # رجع النتيجة لو لقيت ثغرة
    except:
        return None
    return None
# الدالة الرئيسية
def scan_lfi_bulk_fast(place):
    targets_file = f"{place}/Parameters.txt"
    current_dir = os.path.dirname(os.path.abspath(__file__))
    payloads_file = os.path.join(current_dir, 'WordLists', 'LFI.txt')
    current_tool_dir = os.path.dirname(os.path.abspath(__file__))
    if payloads_file is None:
        payloads_file = os.path.join(current_tool_dir, "WordLists", "LFI.txt")

    # قراءة الملفات
    if not os.path.exists(payloads_file): return []
    with open(payloads_file, "r") as f:
        payloads = [l.strip() for l in f.readlines() if l.strip()]

    if not os.path.exists(targets_file): return []
    with open(targets_file, "r") as f:
        targets = [l.strip() for l in f.readlines() if l.strip()]

    success_indicators = ["root:x:0:0", "daemon:x", "[boot loader]", "win.ini"]
    vulnerable_findings = []

    print(colored(f"[*] Turbo Mode ON 🚀 - Scanning {len(targets)} targets with {len(payloads)} payloads...", "cyan"))

    # هنا السحر: بنشغل 10 عمال (Threads) يشتغلوا مع بعض
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        for url in targets:
            print(colored(f"[*] Scanning Target: {url}", "white"))

            # تجهيز المهام
            future_to_payload = {executor.submit(check_single_payload, url, p, success_indicators): p for p in payloads}

            for future in concurrent.futures.as_completed(future_to_payload):
                result = future.result()
                if result:
                    full_url, payload, indicator = result
                    print(colored(f"    [+] VULN FOUND! 🚨 {payload}", "green", attrs=['bold']))
                    vulnerable_findings.append({"target": url, "payload": payload, "evidence": indicator})

                    # (اختياري) لو عايز توقف باقي البايلودز لنفس اللينك عشان تنجز
                    # هنا الموضوع صعب شوية في الثريدنج، بس كمل عادي السرعة هتعوضك

    return vulnerable_findings
def scan_lfi_bulk( place):
    print(colored(f"\n[*] Starting Bulk LFI Scan...", "blue", attrs=['bold']))
    targets_file = f"{place}/Parameters.txt"
    current_dir=os.path.dirname(os.path.abspath(__file__))
    payloads_file=os.path.join(current_dir, 'WordLists','LFI.txt')
    print(payloads_file)
    # 1. قراءة التارجتس (اللينكات) من الفايل
    try:
        with open(targets_file, "r") as f:
            # بنشيل المسافات والسطر الجديد ونتأكد إن السطر مش فاضي
            targets = [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(colored(f"[!] Error: Targets file '{targets_file}' not found!", "red"))
        return []

    # 2. قراءة البايلودز
    try:
        with open(payloads_file, "r") as f:
            payloads = [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(colored(f"[!] Error: Payloads file '{payloads_file}' not found!", "red"))
        return []

    # علامات نجاح الثغرة
    success_indicators = ["root:x:0:0", "daemon:x", "[boot loader]", "win.ini"]

    # قائمة لتخزين النتايج الإيجابية فقط
    vulnerable_findings = []

    print(colored(f"[*] Loaded {len(targets)} targets and {len(payloads)} payloads.\n", "cyan"))

    # --- بداية الـ Fuzzing ---

    # اللوب الأولى: تمسك لينك لينك
    for url in targets:
        print(colored(f"[*] Scanning: {url}", "white"))

        is_vuln_found = False  # علم عشان نعرف لو لقينا حاجة في اللينك ده

        # اللوب الثانية: تجرب البايلودز على اللينك ده
        for payload in payloads:

            # تجهيز الرابط (تأكد إن اللينك في الفايل آخره علامة =)
            # لو اللينك مش آخره = ممكن تزودها هنا بالكود لو حابب
            target_url = f"{url}{payload}"

            try:
                response = requests.get(target_url, timeout=0.5)  # Timeout سريع عشان ننجز

                # فحص الرد
                for indicator in success_indicators:
                    if indicator in response.text:
                        # !!! ثغرة لقيتها !!!
                        print(colored(f"    [+] VULN FOUND! Payload: {payload}", "green", attrs=['bold']))

                        # سجل النتيجة
                        finding = {
                            "target": url,
                            "payload": payload,
                            "full_url": target_url,
                            "evidence": indicator
                        }
                        vulnerable_findings.append(finding)

                        is_vuln_found = True
                        break  # اخرج من لوب الـ indicators

                if is_vuln_found:
                    break  # اخرج من لوب الـ payloads (عشان اللينك ده خلاص اتعرف إنه مصاب)

            except requests.exceptions.RequestException:
                # لو اللينك ميت أو السيرفر عمل بلوك، فوت وجرب اللي بعده
                continue

        # لو خلصنا كل البايلودز ومفيش حاجة ظهرت للينك ده
        if not is_vuln_found:
            pass  # كمل على اللينك اللي بعده في صمت (أو اطبع إنه سليم لو حابب)

    print(colored(f"\n[+] Scan Finished. Found {len(vulnerable_findings)} vulnerabilities.", "yellow", attrs=['bold']))
    return vulnerable_findings
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
            "lfi": read_lines("lfi.txt"),  # أو lfi_nuclei.txt
            "ssrf": read_lines("ssrf.txt"),
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

        prompt = f"Analyze this vulnerability report and suggest fixes: {json_data}"
        response = model.generate_content(prompt)

        # احفظ النتيجة في فايل جديد
        with open(place+"/AI_Report.md", "w") as f:
            f.write(response.text)

        print("[+] AI Report Generated: AI_Report.md")

    except Exception as e:
        print(f"[!] AI Error: {e}")