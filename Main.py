
import Checker
import ConfigCreator
import telegram
import argments
from termcolor import colored
import RecTool
required_libs = ["termcolor","pyfiglet"]
from pyfiglet import Figlet

for lib in required_libs:
    RecTool.install_and_import(lib)
f = Figlet(font='slant')
print(colored(f.renderText('RecTool'), 'red'))
options = argments.setarguments()
if options.telegram :
    print("Go to "+colored("@RecToolbot",color='cyan')+" in telegram chat and send"+colored(" /start ",'red') )
    print("Get your chat id from "+colored("@userinfobot",'cyan')+" and send"+colored(" /start ",'red') )
    print("  " )
    BOT_TOKEN = "8562953467:AAHLJdPliM5RsvOKiXpI5yr3LSGJ5jVn65w"
    chat_id = input(colored("Enter your Telegram chat ID: ","cyan"))
    telegram.send_telegram_message("WE WILL SEND YOU EVERTHING",BOT_TOKEN,chat_id)




if(options.place!=None):
    place=options.place.rstrip("/")
else:
    place="."

website=options.website
if options.api :
    ConfigCreator.create_api_configs(place)
Checker.setup_environment()


try:
     print(colored(f"[+] subEnum Starting: {website}", "yellow",attrs=['bold']))
     RecTool.subdumainEnum(website,place)
     print(colored(f"[+] crawling Starting: {website}", "yellow",attrs=['bold'] ))
     RecTool.deepCrawl(website,place)
     print(colored(f"[+] Downloading: {website}", "yellow",attrs=['bold']))
     RecTool.downloadImportant(place)
     print(colored(f"[+] SQLI Starting: {website}", "yellow",attrs=['bold']))
     RecTool.SQLI(place)
     print(colored(f"[+] XSS Starting: {website}", "yellow",attrs=['bold']))
     RecTool.XSS(place)
     total=RecTool.SumrizeTxt(website, place)
     print(colored(f"[+] cms: {website}", "yellow",attrs=['bold']))
     RecTool.scan_cms(website, place)
     print(colored(f"[+] infoDis: {website}", "yellow",attrs=['bold']))
     RecTool.scan_info_disclosure_nikto(website, place)
     print(colored(f"[+] CVESearch: {website}", "yellow",attrs=['bold']))
     RecTool.scan_cve_full(website, place)
     telegram.send_telegram_message(total,BOT_TOKEN,chat_id)


except Exception as e:
    print(colored("[-] Error occured while scanning",'red'))











