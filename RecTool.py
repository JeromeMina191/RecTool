import json
import os
import shutil
import subprocess

import requests

import argments
import re
from termcolor import colored

options=argments.setarguments()

########################################
#########     SUBDUMAIN #########
def subfinder(website, place):
    print(colored(f"[+] subfinder Start: {website}", "cyan"))
    if options.api:
        command = f"subfinder -d {website} -all -provider-config {place}/my_configsa/subfinder_config.yaml > {place}/subfinderOutput.txt"
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
    merge_and_clean(place)
def merge_and_clean(path):
    try:
        print(colored("[+] Merging files and removing duplicates...","cyan"))
        command = f"sort -u {path}/subfinderOutput.txt {path}/assetFOutput.txt {path}/amassOutput.txt > {path}/finalSubs.txt"
        subprocess.run(command, shell=True)
        print(colored("[+] Done! Saved in finalsubs.txt","cyan"))

    except Exception as e:
        print(colored("[-] Error occured while merging files",'red'))
def clean_text(text, unwanted_words):

    for word in unwanted_words:
        text = text.replace(word, "")
    return text




########################################
#########  CRAWLING  #########
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
                crawlig(link, place)
        extract_parameter_urls(place)
    except Exception as e:
        print(colored("[-] Error occured while crawlingDeep", 'red'))
        extract_parameter_urls(place)




########################################
#########     EXTRACT AND DOWNLOAD  #########
def extract_parameter_urls(place):
    input_file=place+"/hackrwlerurls.txt"
    output_file=place+"/Parameters.txt"
    print(f"[+] Filtering URLs with parameters from {input_file}...")
    ignored_extensions = (".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".svg")
    count = 0
    try:
        with open(input_file, 'r') as f_in, open(output_file, 'w') as f_out:
            for line in f_in:
                url = line.strip()
                if "?" in url and "=" in url:
                    if not url.lower().endswith(ignored_extensions):
                        f_out.write(url + "\n")
                        count += 1
        print(colored(f"[+] Done! Found {count} parameter URLs. Saved to {output_file}","cyan") )

    except FileNotFoundError:
        print(colored(f"[-] Error: File {input_file} not found!","red") )
def extract_files_urls(place,type):
    input_file=place+f"/hackrwlerurls.txt"
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
    os.makedirs(place+f"/{type}_files", exist_ok=True)

    for url in php_links:
        print(f"[+] Downloading: {url}")

        command = [
            "wget",
            "-q",
            "-P", place+f"/{type}",
            "--no-check-certificate",
            "--content-disposition",
            url
        ]

        subprocess.run(command)
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

def scan_sqli(url, place):
    print(colored(f"[+] Scanning for SQLi: {url}", "cyan"))
    command = f"sqlmap -u '{url}' --batch --level 1 --risk 1 --dbs"
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
def SQLI( place):
    try:
        with open(place + "/Parameters.txt", "r") as file:
            links = file.readlines()
        for link in links:
            link = link.strip()
            if link:
                scan_sqli(link, place)
    except Exception as e:
        print(colored("[-] Error occured while scanning", 'red'))

########################################
############   XSS   ################
def scan_xss(url, place):
    print(colored(f"[+] Scanning for XSS: {url}","cyan"))

    # --no-color: مهم جداً عشان النصوص تتخزن نظيفة من غير رموز الألوان
    command = f"dalfox url '{url}' --no-color"

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
def XSS( place):
    try:
        with open(place + "/Parameters.txt", "r") as file:
            links = file.readlines()
        for link in links:
            link = link.strip()
            if link:
                scan_xss(link, place)
    except Exception as e:
        print(colored("[-] Error occured while XSS", 'red'))


########################################
############   INFODIS AND CMS   ################
def scan_info_disclosure_nikto(url, place):
    print(colored(f"[+] Scanning for Info Disclosure using Nikto: {url}", "cyan"))

    # تفاصيل الأمر:
    # -h: الهدف
    # -maxtime 2m: بحد اقصى دقيقتين للفحص (عشان لو السيرفر تقيل ميعطلش التوول)
    # -Tuning 90b: يركز على ملفات الـ SQL والملفات المهمة وكشف المعلومات (تسريع الفحص)
    # -nointeractive: عشان ميسألش اسئلة تعطل السكريبت
    command = f"nikto -h '{url}' -maxtime 2m -nointeractive"

    try:
        # Nikto بياخد وقت، فممكن نستخدم timeout في البايثون كمان
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        output_lines = result.stdout.splitlines()
        found_info = []

        for line in output_lines:
            # Nikto بيحط علامة + قدام أي حاجة مهمة لقاها
            if line.startswith("+"):
                # تنظيف السطر
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
                if line.strip().startswith("Target:")|"[VULN CHECK] Target" :
                    count += 1
        return count
    except FileNotFoundError:
        return 0  # لو الملف مش موجود (يعني مفيش ثغرات لسه)
def SumrizeTxt(website,place):
    try:
        amass = get_file_length(place + "/amassOutput.txt")
        assetfinder = get_file_length(place + "/assetFOutput.txt")
        subfinder = get_file_length(place + "/subfinderOutput.txt")
        totalSubs = get_file_length(place + "/finalSubs.txt")
        TotalParams = get_file_length(place + "/Parameters.txt")
        sqli = count_vulnerabilities(place + "/vulnerable_sqli.txt")
        xss = count_vulnerabilities(place + "/vulnerable_xss.txt")
        php = get_file_length(place + "/php.txt")
        js = get_file_length(place + "/js.txt")
        json=get_file_length(place + "/json.txt")
        html = get_file_length(place + "/html.txt")
        cve = count_vulnerabilities(place + "/cve_exploits.txt")
        return f"""
Welcome to RecTool!
Your website is {website}
we found Subdomains:
amass: {amass}
assetfinder: {assetfinder}
subfinder: {subfinder}
total Uniqe Subs: {totalSubs}
we found parameters: {TotalParams}
We found vulnerable XSS: {xss}
we found vulnerable Sqli: {sqli}
we found HTML page: {html}
we found json: {json}
we found php: {php}
we found JS: {js}
we found CVE: {cve}
"""
    except Exception as e:
        print(colored("[-] Error occured while Make Masege", 'red'))


######################################
########     CVE  Detector   ########
# ============================================================
# 1. دالة تنظيف الإصدار (The Cleaner)
# وظيفتها: تحويل ['1.19.0'] أو 5.6.40-ubuntu لـ 1.19.0 فقط
# ============================================================
def clean_version(raw_version):
    # تحويل القائمة لنص
    if isinstance(raw_version, list):
        if len(raw_version) > 0:
            ver_str = str(raw_version[0])
        else:
            return ""
    else:
        ver_str = str(raw_version)

    # استخدام Regex لاستخراج الأرقام فقط (Major.Minor.Patch)
    match = re.search(r'([0-9]+\.[0-9]+(\.[0-9]+)?)', ver_str)

    if match:
        return match.group(1)  # يرجع الرقم الصافي
    return ver_str  # يرجع النص زي ما هو لو فشل التنظيف
# ============================================================
# 2. دالة البحث عن الثغرات (Exploit Searcher)
# وظيفتها: البحث في SearchSploit وحفظ النتائج
# ============================================================
def check_exploits_searchsploit(product_name, version, place):
    # تكوين جملة البحث
    if version:
        query = f"{product_name} {version}"
        print(colored(f"       [*] Searching Exploits for: {query}...", "cyan"))
    else:
        query = f"{product_name}"
        print(colored(f"       [*] Searching Generic Exploits for: {query}...", "yellow"))

    # تشغيل SearchSploit وإخراج JSON
    command = f"searchsploit '{query}' --json"

    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        try:
            data = json.loads(result.stdout)
            exploits = data.get('RESULTS_EXPLOIT', [])

            if exploits:
                print(colored(f"       [!] FOUND {len(exploits)} Exploits/CVEs!", "red", attrs=['bold']))

                # حفظ التقرير
                report_file = os.path.join(place, "cve_exploits.txt")
                with open(report_file, "a") as f:
                    f.write(f"\n{'=' * 50}\n")
                    f.write(f"[VULN CHECK] Target: {query}\n")
                    f.write(f"{'=' * 50}\n")

                    # حفظ أول 5 نتائج فقط
                    for ex in exploits[:5]:
                        title = ex.get('Title', 'No Title')
                        edb_id = ex.get('EDB-ID', 'N/A')

                        # طباعة مختصرة على الشاشة
                        print(colored(f"       └── [EDB-{edb_id}] {title[:60]}...", "yellow"))

                        # كتابة التفاصيل في الملف
                        f.write(f"ID: {edb_id}\nTitle: {title}\nLink: https://www.exploit-db.com/exploits/{edb_id}\n")
                        f.write("-" * 30 + "\n")
            else:
                print(colored("       [-] No exploits found in local DB.", "green"))

        except json.JSONDecodeError:
            # لو ملقاش نتائج أحياناً مبيطلعش JSON
            print(colored("       [-] No results.", "white"))

    except Exception as e:
        print(colored(f"       [-] Error running searchsploit: {e}", "red"))
# ============================================================
# 3. الدالة الرئيسية (Manager)
# وظيفتها: تشغيل WhatWeb وتوزيع المهام
# ============================================================
def scan_cve_full(url, place):
    print(colored(f"\n[+] Starting Advanced CMS & Vulnerability Analysis: {url}", "blue", attrs=['bold']))

    json_file = os.path.join(place, "whatweb_temp.json")

    # تشغيل WhatWeb
    command = f"whatweb {url} --log-json {json_file} --color=never"

    try:
        # تشغيل في الخلفية عشان ميزعجش المستخدم
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

                    # قائمة التقنيات المهمة اللي هندور وراها
                    important_techs = [
                        'WordPress', 'Apache', 'nginx', 'PHP', 'Joomla',
                        'Drupal', 'Microsoft-IIS', 'Tomcat', 'Python', 'OpenSSL'
                    ]

                    for name, info in plugins.items():
                        raw_version = info.get('version', '')

                        # 1. تنظيف الإصدار
                        clean_ver = clean_version(raw_version)

                        # 2. طباعة النتيجة
                        display_ver = clean_ver if clean_ver else "Unknown"
                        print(f"   └── {name} : {display_ver}")

                        # 3. البحث عن ثغرات لو التقنية مهمة
                        if name in important_techs:
                            check_exploits_searchsploit(name, clean_ver, place)

                except json.JSONDecodeError:
                    pass

            # (اختياري) مسح ملف الـ JSON المؤقت بعد ما نخلص
            # os.remove(json_file)

        else:
            print(colored("[-] WhatWeb output file not found.", "red"))

    except Exception as e:
        print(colored(f"[-] Error in CVE Module: {e}", "red"))

######################################
########     proxy  support   ########
