import os

import json

import Checker
import ConfigCreator
import telegram
import argments
from termcolor import colored
import RecToolFn
from pyfiglet import Figlet
from dotenv import load_dotenv
# 1. هات مسار الفولدر اللي فيه ملف البايثون الحالي (RecTool.py)
current_dir = os.path.dirname(os.path.abspath(__file__))

# 2. ركب عليه اسم ملف .env
env_path = os.path.join(current_dir, '.env')

loaded = load_dotenv(env_path)

api_key = os.getenv("GEMINI_API_KEY")
load_dotenv()

f = Figlet(font='slant')
print(colored(f.renderText('RecTool'), 'red'))
options = argments.setarguments()
if options.telegram :
    print("Go to "+colored("@RecToolbot",color='cyan')+" in telegram chat and send"+colored(" /start ",'red') )
    print("Get your chat id from "+colored("@userinfobot",'cyan')+" and send"+colored(" /start ",'red') )
    BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    telegram.send_telegram_message("WE WILL SEND YOU EVERTHING",BOT_TOKEN,chat_id)
if(options.place!=None):
    place=options.place.rstrip("/")
else:
    place="."
website=options.website
if options.api :
    ConfigCreator.create_api_configs(place)
Checker.setup_environment()
print(colored("[+] make sure you are running tor befor use it!", "yellow"))
print(colored("[+] to run it :", "cyan")+colored(" sudo apt install -y tor","red",))
print(colored(" sudo service tor start","red"))
tor_input = input(colored("[?] Do you want to use Tor Proxy? (y/n): ", "yellow",attrs=['bold'])).lower().strip()
use_tor_mode = False
if tor_input == 'y':
        # لازم نتأكد إن الخدمة شغالة الأول
        if RecToolFn.is_tor_running():
            use_tor_mode = True
            print(colored("[+] Tor Mode Enabled. Traffic will be anonymized.", "green",attrs=['bold']))
        else:
            print(colored("[-] Tor service is NOT running! Continuing without Proxy.", "red"))
            print(colored("    Hint: Run 'sudo service tor start' in terminal.", "white"))
            use_tor_mode = False
try:

     print(colored(f"[+] subEnum Starting: {website}", "yellow",attrs=['bold']))
     RecToolFn.subdumainEnum(website,place)
     print(colored(f"[+] crawling Starting: {website}", "yellow",attrs=['bold'] ))
     RecToolFn.deepCrawl(website,place)
     print(colored(f"[+] Downloading: {website}", "yellow",attrs=['bold']))
     RecToolFn.downloadImportant(place)
     print(colored(f"[+] SQLI Starting: {website}", "yellow",attrs=['bold']))
     RecToolFn.SQLI(place,use_tor_mode)
     print(colored(f"[+] XSS Starting: {website}", "yellow",attrs=['bold']))
     RecToolFn.XSS(place,use_tor_mode)
     print(colored(f"[+] SSRF: {website}", "yellow",attrs=['bold']))
     RecToolFn.scan_ssrf_mass(place, use_tor_mode)
     print(colored(f"[+] LFI: {website}", "yellow",attrs=['bold']))
     RecToolFn.scan_lfi_nuclei(place, use_tor_mode)
     print(colored(f"[+] cms: {website}", "yellow",attrs=['bold']))
     RecToolFn.scan_cms(website, place)
     print(colored(f"[+] infoDis: {website}", "yellow",attrs=['bold']))
     RecToolFn.scan_info_disclosure_nikto(website, place)
     print(colored(f"[+] CVESearch: {website}", "yellow",attrs=['bold']))
     RecToolFn.scan_cve_full(website, place)
     RecToolFn.scan_cve_nuclei(place, use_tor_mode)
     RecToolFn.generate_json_report(website, place)
     if options.telegram:
        total = RecToolFn.SumrizeTxt(website, place)
        telegram.send_telegram_message(total,BOT_TOKEN,chat_id)
except Exception as e:
     print(colored("[-] Error occured while scanning",'red'))
json_file_path =place +"/Final_Report.json"  # أو المتغير اللي شايل مسار الملف
# 2. اتأكد إن الملف موجود أصلاً (عشان الكود مايضربش لو الاسكان فشل)
if os.path.exists(json_file_path):

    # 3. افتح الملف واقرأ اللي فيه وحوله لمتغير (Dictionary/List)
    with open(json_file_path, 'r', encoding='utf-8') as f:
        data_from_file = json.load(f)  # السطر ده السحر كله

    # 4. دلوقتي ابعت المتغير ده لدالة الـ AI

    RecToolFn.generate_ai_report(os.getenv("GEMINI_API_KEY"),data_from_file,place)

else:
    print(f"[!] Error: File {json_file_path} not found!")









