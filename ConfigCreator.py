import os
from termcolor import colored
def create_api_configs(place):
    print(colored("\n--- [ API Configuration Setup (Amass v5 & Subfinder) ] ---", "yellow", attrs=['bold']))
    keys = {
        "shodan": input(colored("[?] Enter Shodan API Key: ", "green")).strip(),
        "securitytrails": input(colored("[?] Enter SecurityTrails API Key: ", "green")).strip(),
        "github": input(colored("[?] Enter GitHub Token: ", "green")).strip(),
        "virustotal": input(colored("[?] Enter VirusTotal API Key: ", "green")).strip(),
        "chaos": input(colored("[?] Enter Chaos Key: ", "green")).strip()
    }

    config_dir =place+"/my_configs"
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)


    print(colored("\n[*] Generating Subfinder config...", "blue"))
    subfinder_yaml = "resolvers:\n  - 1.1.1.1\n  - 8.8.8.8\nsources:\n"

    if keys["shodan"]: subfinder_yaml += f"  shodan:\n    - {keys['shodan']}\n"
    if keys["securitytrails"]: subfinder_yaml += f"  securitytrails:\n    - {keys['securitytrails']}\n"
    if keys["github"]: subfinder_yaml += f"  github:\n    - {keys['github']}\n"
    if keys["virustotal"]: subfinder_yaml += f"  virustotal:\n    - {keys['virustotal']}\n"
    if keys["chaos"]: subfinder_yaml += f"  chaos:\n    - {keys['chaos']}\n"

    subfinder_path = os.path.join(config_dir, "subfinder_config.yaml")
    with open(subfinder_path, "w") as f:
        f.write(subfinder_yaml)

    # ==========================================

    print(colored("[*] Generating Amass v5 config (YAML)...", "blue"))

    amass_yaml = "options:\n"
    amass_yaml += "  verbose: true\n"
    amass_yaml += "data_sources:\n"

    if keys["securitytrails"]:
        amass_yaml += f"""  - name: SecurityTrails
    creds:
      apikey: {keys['securitytrails']}
"""
    if keys["github"]:
        amass_yaml += f"""  - name: GitHub
    creds:
      apikey: {keys['github']}
"""
    if keys["virustotal"]:
        amass_yaml += f"""  - name: VirusTotal
    creds:
      apikey: {keys['virustotal']}
"""
    if keys["shodan"]:
        amass_yaml += f"""  - name: Shodan
    creds:
      apikey: {keys['shodan']}
"""
    if keys["chaos"]:
        amass_yaml += f"""  - name: Chaos
    creds:
      apikey: {keys['chaos']}
"""

    amass_path = os.path.join(config_dir, "amass_config.yaml")
    with open(amass_path, "w") as f:
        f.write(amass_yaml)

    print(colored(f"[+] Configs updated! ", "green", attrs=['bold']))
    return subfinder_path, amass_path

