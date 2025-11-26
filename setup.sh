#!/bin/bash

echo "[+] Installing Dependencies..."

# 1. تحديث النظام وتثبيت Go (لأن dalfox معمولة بـ Go)
sudo apt update
sudo apt install -y golang git

# 2. تثبيت Dalfox
echo "[+] Installing Dalfox..."
go install github.com/hahwul/dalfox/v2@latest

# 3. نقل الأداة لمكان عام عشان تشتغل من أي مكان
sudo cp ~/go/bin/dalfox /usr/local/bin/

echo "[+] Installation Done! You can run the tool now."
