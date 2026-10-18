#!/bin/bash

# ألوان عشان شكل السكربت يكون احترافي في الـ Terminal
GREEN="\033[1;32m"
BLUE="\033[1;34m"
RED="\033[1;31m"
RESET="\033[0m"

echo -e "${BLUE}[*] Starting Marsadix Dependencies Installer...${RESET}"

# 1. التأكد من توفر الصلاحيات (Sudo)
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[-] Please run this script with sudo: sudo ./install-tools.sh${RESET}"
  exit 1
fi

# 2. تحديث النظام وتنزيل المتطلبات الأساسية
echo -e "${GREEN}[+] Updating system and installing base prerequisites...${RESET}"
apt update -y
apt install -y curl wget git unzip python3 python3-venv python3-pip

# 3. التأكد من تثبيت لغة Go
if ! command -v go &> /dev/null; then
    echo -e "${GREEN}[+] Installing Golang...${RESET}"
    apt install -y golang-go
else
    echo -e "${BLUE}[*] Golang is already installed.${RESET}"
fi

# إعداد مسار Go
export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

# 4. تثبيت أدوات الـ Recon اللي بتعتمد على Go
echo -e "${GREEN}[+] Installing Subfinder, Assetfinder, and Chaos...${RESET}"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest

# نقل الأدوات لمسار النظام عشان بايثون يشوفها بسهولة
cp $HOME/go/bin/subfinder /usr/local/bin/ 2>/dev/null
cp $HOME/go/bin/assetfinder /usr/local/bin/ 2>/dev/null
cp $HOME/go/bin/chaos /usr/local/bin/ 2>/dev/null

# 5. تثبيت Amass
echo -e "${GREEN}[+] Installing Amass...${RESET}"
apt install -y amass

# 6. تثبيت Findomain
if ! command -v findomain &> /dev/null; then
    echo -e "${GREEN}[+] Installing Findomain...${RESET}"
    curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux
    chmod +x findomain-linux
    mv findomain-linux /usr/local/bin/findomain
else
    echo -e "${BLUE}[*] Findomain is already installed.${RESET}"
fi

echo -e "${GREEN}[+] All external tools installed successfully!${RESET}"
echo -e "${BLUE}[*] You can now run Marsadix.${RESET}"
