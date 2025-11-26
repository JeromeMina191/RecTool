import shutil
from pyfiglet import Figlet
import recon
import telegram
import argments
from termcolor import colored
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

if options.infoDis|options.all:
    if(shutil.which("nikto")):
        print(colored("[+] infoDis start on ",'cyan') + options.website)
        result=recon.infoDis(options.website, options.place)
        print(colored("[+] infoDis done",'cyan'))
        telegram.send_telegram_message(result,BOT_TOKEN,chat_id)
    else:
        print(colored("[+] infoDis not found ",'red'))

if options.cmsWhat|options.all :
    if shutil.which("whatweb"):
        print((colored("[+]CMS Starting ",'cyan') + options.website))
        result=recon.cmswhatweb(options.website, options.place)
        telegram.send_telegram_message(result,BOT_TOKEN,chat_id)
        print(colored("[+] CMS done",'cyan'))
    else:
        print(colored("[-] whatweb not found ",'red'))
if options.subdoumain|options.all :
    if shutil.which("subfinder"):
        print(colored("[+] subfinder start on ",'cyan') + options.website)
        result=recon.subfinder(options.website, options.place)
        telegram.send_telegram_message(result, BOT_TOKEN, chat_id)
        print(colored("[+] subfinder done",'cyan'))

    else:
        print(colored("[-] subfinder not found",'red'))
    if shutil.which("amasss"):
        print(colored("[+] amass start on " ,'cyan')+ options.website)
        result= recon.amass(options.website, options.place)
        telegram.send_telegram_message(result, BOT_TOKEN, chat_id)
        print(colored("[+] amass done",'cyan'))
    else:
        print(colored("[-] amass not found",'red'))
    if shutil.which("assetfinder"):
        print(colored("[+] assetfinder start on ",'cyan') + options.website)
        result= recon.assetfinder(options.website, options.place)
        telegram.send_telegram_message(result, BOT_TOKEN, chat_id)
        print(colored("[+] assetfinder done",'cyan'))
    else:
        print(colored("[-] assetfinder not found",'red'))
    if shutil.which("hakrawler"):
        print(colored("[+] hakrawler start on ",'cyan') + options.website)
        result=recon.hakrawler(options.website, options.place)
        print(colored("[+] hakrawler done",'cyan'))
    else:
        print(colored("[-] hakrawler not found",'red'))
    if(options.place != None):
        recon.calculateSubs(options.place)
        with open(options.place +"/out.txt", "r", encoding="utf-8") as f:
            res = [amassf.strip() for amassf in f]

        result="the totalUniqe found: " + str(len(res))
        telegram.send_telegram_message(result, BOT_TOKEN, chat_id)
recon.sqlInjection(options.website, options.place)