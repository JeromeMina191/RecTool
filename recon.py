import shutil
import subprocess
from termcolor import colored





# SubDomain Enum Tools
def subfinder(website, place):
    try:
        if (place != None):
            subprocess.run("subfinder -d "+website+" > "+place+"/subfinderOutput.txt",capture_output=True,text=True,timeout=120, shell=True)
            with open(place+"/subfinderOutput.txt", "r", encoding="utf-8") as f:
                result = [amassf.strip() for amassf in f]
            return "the subfinder found: "+str(len(result))
        else:
            result=subprocess.run("subfinder -d " + website ,capture_output=True,text=True,timeout=120, shell=True)
            print(result.stdout)
            return result.stdout
    except subprocess.TimeoutExpired:
        print(colored("subfinder timed out",'red'))


def amass(website, place):
    try:
        if (place != None):
            subprocess.run("amass enum -passive -d "+website+" > "+place+"/amassOutput.txt",capture_output=True,text=True,timeout=120, shell=True)
            with open(place+"/amassOutput.txt", "r", encoding="utf-8") as f:
                result = [amassf.strip() for amassf in f]
            return "the amass found: "+str(len(result))
        else:
            result=subprocess.run("amass enum -passive -d "+website,capture_output=True,text=True,timeout=120 , shell=True)
            print(result.stdout)
            return result.stdout
    except subprocess.TimeoutExpired:
        with open(place + "/amassOutput.txt", "r", encoding="utf-8") as f:
            result = [amassf.strip() for amassf in f]
        print(colored("amass timed out",'red'))
        return "the amass found: "+str(len(result))
def assetfinder(website, place):
    try:
        if (place != None):
            subprocess.run("assetfinder --subs-only "+website+" > "+place+"/assetFOutput.txt",capture_output=True,text=True,timeout=120, shell=True)
            with open(place+"/assetFOutput.txt", "r", encoding="utf-8") as f:
                result = [amassf.strip() for amassf in f]

            return "the assetfinder found: "+str(len(result))

        else:
           result= subprocess.run("assetfinder --subs-only "+website,capture_output=True,text=True ,timeout=120, shell=True)
           print(result.stdout)
           return result.stdout
    except subprocess.TimeoutExpired:
        print(colored("assetfinder timed out",'red'))

###########################
#calc
def calculateSubs(place):

    if shutil.which("amssass"):
        placeSub = place + "/amassOutput.txt"
        with open(placeSub, "r", encoding="utf-8") as f:
            amassf = [amassf.strip() for amassf in f]
            print("done open amass")

    if shutil.which("subfinder"):
        placeSub = place + "/subfinderOutput.txt"
        with open(placeSub, "r", encoding="utf-8") as f:
            sbfinder = [sbfinder.strip() for sbfinder in f]
            print("done open subfinder")

    if shutil.which("assetfinder"):
        placeSub = place + "/assetFOutput.txt"
        with open(placeSub, "r", encoding="utf-8") as f:
            assetbfinder = [sbfinder.strip() for sbfinder in f]
            print("done open assetfinder")
    if shutil.which("hakrawler"):
        placeSub = place + "/hackrwlerSubs.txt"
        with open(placeSub, "r", encoding="utf-8") as f:
            hackrawlersubs = [hackrawlersubs.strip() for hackrawlersubs in f]
            print("done open hackrawlersubs")

    merged = list(set(sbfinder) | set(assetbfinder) | set(hackrawlersubs) )

    with open(place+"/out.txt", "w", encoding="utf-8") as f:
        for item in merged:
            f.write(item + "\n")
        print("result created")


#######################################

#          crawling
def hakrawler(website, place):
    try:
        if (place != None):
            subprocess.run("echo https://www."+website+" | "+"hakrawler -subs  "+" > "+place+"/hackrwlerSubs.txt" ,capture_output=True,text=True,timeout=120, shell=True)
            subprocess.run("echo https://www."+website+" | "+"hakrawler -u "+" > "+place+"/hackrwlerurls.txt" ,capture_output=True,text=True,timeout=120, shell=True)
        else:
            subprocess.run( "echo https://www." + website + " | " + "hakrawler -subs  ",capture_output=True,text=True, timeout=120, shell=True)
            subprocess.run("echo https://www."+website+" | "+"hakrawler -u ",capture_output=True,text=True, timeout=120,shell=True)
    except subprocess.TimeoutExpired:
        print(colored("hakrawler timed out",'red'))

def hakrawlerForInj(website, place):
    try:
        if (place != None):
            subprocess.run("echo "+website+" | "+"hakrawler | grep "+"="+" > "+place+"/Parameters.txt" ,capture_output=True,text=True,timeout=120, shell=True)
        else:
            subprocess.run(
                "echo " + website + " | " + "hakrawler | grep " + "=" + " > " + "./Parameters.txt",
                capture_output=True, text=True, timeout=120, shell=True)

    except subprocess.TimeoutExpired:
         print(colored("hakrawler timed out",'red'))

######################################
def sqlInjection(website, place):
    try:
        hakrawlerForInj(website, place)
        if (place != None):
            placePath=place
        else:
            placePath="."
        with open(placePath+"/Parameters.txt", "r") as file:
            links = file.readlines()
        for link in links:
            link = link.strip()
            if link:
                command = f"sqlmap -u '{link}' --batch --level 1 --risk 1 --dbs"
                result= subprocess.call(command, text=True, timeout=6000, shell=True)
                print("done sql injection")
            else:
                print("[-] Not Vulnerable.")


    except subprocess.TimeoutExpired:
        print(colored("sql injection timed out",'red'))


def scan_sqli(url):
    print(f"[+] Scanning for SQLi: {url}")
    command = f"sqlmap -u '{url}' --batch --level 1 --risk 1 --dbs"
    try:
        # تشغيل الأمر والتقاط المخرجات
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        # البحث في المخرجات عن كلمة تدل على النجاح
        if "available databases" in result.stdout:
            print(f"[!!!] VULNERABLE TO SQLi: {url}")
            with open("vulnerable_sqli.txt", "a") as f:
                f.write(url + "\n")
        else:
            print("[-] Not Vulnerable.")

    except Exception as e:
        print(f"Error scanning {url}: {e}")
#               cms FP
def cmswhatweb(website, place):
    try:
        if (place!= None):
            subprocess.run("whatweb -v "+website+ " > "+place+"/CmsFP.txt" ,capture_output=True,timeout=120,text=True, shell=True)
            with open(place+"/CmsFP.txt", "r", encoding="utf-8") as f:
                file_content = f.read()
            return file_content
        else:
            result= subprocess.run("whatweb -v "+website ,capture_output=True,text=True ,timeout=120,shell=True)
            print(result.stdout)
            return result.stdout
    except subprocess.TimeoutExpired:
        print(colored("whatweb timed out",'red'))


######################################

#              info D
def infoDis(website, place):
    try:
        if (place!= None):
            subprocess.run("nikto -h  "+website+ " > "+place+"/infoDis.txt" ,capture_output=True,text=True,timeout=120, shell=True)
            with open(place+"/CmsFP.txt", "r", encoding="utf-8") as f:
                file_content = f.read()
            return file_content
        else:
            result=subprocess.run("nikto -h "+website,capture_output=True,text=True ,timeout=120, shell=True)
            print(result.stdout)
            return result.stdout
    except subprocess.TimeoutExpired:
        print(colored("nikto timed out",'red'))
