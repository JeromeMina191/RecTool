import os
import subprocess
import shutil
from termcolor import colored
def check_and_install(tool_name, install_command):
    if shutil.which(tool_name) is None:
        print(colored(f"[!] {tool_name} not found. Installing...","cyan") )
        try:

            subprocess.run(install_command, shell=True, check=True)
            print(colored(f"[+] {tool_name} installed successfully!","green",attrs=['bold']) )
        except subprocess.CalledProcessError:
            print(colored(f"[-] Failed to install {tool_name}. Please install it manually.",color="red") )

    else:
        print(colored(f"[+] {tool_name} is already installed.","green",attrs=['bold']) )

        if tool_name == "exploitdb" :
            inp = input(colored("Do you want To Update ExploitDB? (y/n)", color="yellow", attrs=['bold']))
            if inp.lower() == "y":
                try:
                    subprocess.run("searchsploit -u", shell=True, check=True)
                    print("[+] ExploitDB Updated Successfully!")
                except Exception:
                    print("[-] Warning: Could not update ExploitDB. Using current version.")


def setup_environment():
    print(colored("--- Checking Requirements ---",color="yellow",attrs=['bold']))

    check_and_install("go", "sudo apt update && sudo apt install -y golang")

    apt_tools = ["sqlmap", "amass", "subfinder", "whatweb", "nikto", "git","exploitdb","nuclei"]
    check_and_install("whatweb", "sudo apt install -y whatweb")
    check_and_install("nikto", "sudo apt install -y nikto")
    for tool in apt_tools:
        check_and_install(tool, f"sudo apt install -y {tool}")
    if shutil.which("katana") is None:
        print(colored("[!] Katana not found. Installing it now...", "yellow"))

        try:
            # محاولة 1: التسطيب عن طريق Go (الطريقة الرسمية والأضمن)
            # بنفترض إن Go متسطب على Kali (وهو غالباً موجود)
            print(colored("[*] Trying to install via Go...", "blue"))

            # أمر التسطيب
            install_cmd = "go install github.com/projectdiscovery/katana/cmd/katana@latest"
            subprocess.run(install_cmd, shell=True, check=True)

            # خطوة مهمة: نقل الملف لمكان عام عشان يشتغل من أي حتة
            # Go بينزل الملفات في ~/go/bin/
            # هننقله لـ /usr/local/bin/
            move_cmd = "sudo cp ~/go/bin/katana /usr/local/bin/ 2>/dev/null || sudo cp /root/go/bin/katana /usr/local/bin/"
            os.system(move_cmd)

            print(colored("[+] Katana installed successfully via Go!", "green",attrs=['bold']))

        except subprocess.CalledProcessError:
            # محاولة 2: لو Go مش موجود، نجرب apt (نسخة كالي)
            print(colored("[!] Go install failed. Trying apt...", "yellow"))
            try:
                subprocess.run("sudo apt update && sudo apt install katana -y", shell=True, check=True)
                print(colored("[+] Katana installed successfully via APT!", "green"))
            except:
                print(colored(
                    "[!] CRITICAL: Failed to install Katana manually. Please install it using: 'sudo apt install katana'",
                    "red"))
                exit()
    else:
        print(colored("[+] Katana is already installed.", "green",attrs=['bold']))

    # Dalfox
    if shutil.which("dalfox") is None:
        print(colored("[!] Installing Dalfox...","cyan"))
        cmd = "go install github.com/hahwul/dalfox/v2@latest && sudo cp ~/go/bin/dalfox /usr/local/bin/"
        subprocess.run(cmd, shell=True)
    else:
        print(colored("[+] Dalfox is ready.","green",attrs=['bold']))

    # Assetfinder
    if shutil.which("assetfinder") is None:
        print(colored("[!] Installing Assetfinder...","cyan"))
        cmd = "go install github.com/tomnomnom/assetfinder@latest && sudo cp ~/go/bin/assetfinder /usr/local/bin/"
        subprocess.run(cmd, shell=True)
    else:
        print(colored("[+] Assetfinder is ready.","green",attrs=['bold']))

    # Hakrawler
    if shutil.which("hakrawler") is None:
        print(colored("[!] Installing Hakrawler...","cyan"))
        cmd = "go install github.com/hakluke/hakrawler@latest && sudo cp ~/go/bin/hakrawler /usr/local/bin/"
        subprocess.run(cmd, shell=True)
    else:
        print(colored("[+] Hakrawler is ready.","green",attrs=['bold']))

    print(colored("\n[ok] All tools are ready to use!\n","green",attrs=['bold']))


