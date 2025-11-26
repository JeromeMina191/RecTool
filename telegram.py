import requests
from termcolor import colored


def send_telegram_message(message,BOT_TOKEN,chat_id):
    if len(message) > 4000:
        for i in range(0, len(message), 4000):
            chunk = message[i:i + 4000]
    else:
        chunk = message
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = {"chat_id": chat_id, "text": chunk}
    r = requests.post(url, data=data)
    if r.status_code == 200:
        print(colored("[+]Message sent successfully",'cyan'))
    else:
        print(colored("[+]Failed to send:",'red'), r.text)


def send_file_content(file_path,BOT_TOKEN,chat_id):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        if len(content) > 4000:
            for i in range(0, len(content), 4000):
                chunk = content[i:i+4000]
                send_telegram_message(chunk)
        else:
            send_telegram_message(content,BOT_TOKEN,chat_id)

    except FileNotFoundError:
        print("NotFound", file_path)
    except Exception as e:
        print("Error:", e)

