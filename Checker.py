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
        if tool_name == "exploitdb":
            try:
                subprocess.run("searchsploit -u", shell=True, check=True)
                print("[+] ExploitDB Updated Successfully!")
            except Exception:
                print("[-] Warning: Could not update ExploitDB. Using current version.")


def setup_environment():
    print(colored("--- Checking Requirements ---",color="yellow",attrs=['bold']))

    check_and_install("go", "sudo apt update && sudo apt install -y golang")

    apt_tools = ["sqlmap", "amass", "subfinder", "whatweb", "nikto", "git","exploitdb"]
    check_and_install("whatweb", "sudo apt install -y whatweb")
    check_and_install("nikto", "sudo apt install -y nikto")
    for tool in apt_tools:
        check_and_install(tool, f"sudo apt install -y {tool}")


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


