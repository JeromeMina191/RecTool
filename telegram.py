import requests
from termcolor import colored


def send_telegram_message(message, bot_token, chat_id):
    if not bot_token or not chat_id:
        return

    api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    try:
        if len(message) <= 4000:
            data = {"chat_id": chat_id, "text": message}
            requests.post(api_url, data=data, timeout=10)
        else:
            for i in range(0, len(message), 4000):
                chunk = message[i:i + 4000]
                data = {"chat_id": chat_id, "text": chunk}
                requests.post(api_url, data=data, timeout=10)



    except Exception as e:
        print(colored(f"[-] Telegram Error: {e}", "red"))


