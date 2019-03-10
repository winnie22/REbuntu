#!/bin/bash

# configuration
INSTDIR="/opt"
APT_PACKAGES=(python-pip python3-pip binwalk unzip g++ gdb gcc make hexedit yara apktool ssdeep tcpdump wireshark ddrescue upx-ucl sqlite3 git openjdk-11-jdk)

PIP_PACKAGES=(oletools)

GHIDRA_URL="https://www.ghidra-sre.org/ghidra_9.0_PUBLIC_20190228.zip"
RADARE2_GIT="https://github.com/radare/radare2"
VOLATILITY_GIT=("https://github.com/volatilityfoundation/volatility" "https://github.com/volatilityfoundation/profiles" "https://github.com/volatilityfoundation/community")
JD_GUI="https://github.com/java-decompiler/jd-gui/releases/download/v1.4.0/jd-gui-1.4.0.jar"
DEX2JAR="https://github.com/pxb1988/dex2jar/files/1867564/dex-tools-2.1-SNAPSHOT.zip"
CFR="https://www.benf.org/other/cfr/cfr-0.140.jar"
PDF_PARSER="http://didierstevens.com/files/software/pdf-parser_V0_7_1.zip"

YARA_RULES=("https://github.com/Yara-Rules/rules" "https://github.com/tenable/yara-rules")

# functions
function print_status_sucess {
	local msg="$1"
	echo "[*] $msg"
}

function print_status_info {
	local msg="$1"
	echo "[+] $msg"
}

function print_status_error {
	local msg="$1"
	echo "[!] $msg"
}

# main
for package in ${APT_PACKAGES[*]}; do
  print_status_info "Installing apt $package"
	DEBIAN_FRONTEND=noninteractive apt -y install $package
done

for package in ${PIP_PACKAGES[*]}; do
	print_status_info "Installing pip $package"
	pip install $package
done

print_status_info "Installing Ghidra"
mkdir -p $INSTDIR
cd $INSTDIR
wget $GHIDRA_URL -O $INSTDIR/ghidra.zip
unzip -o ghidra.zip

print_status_info "Installing Radare2"
git clone $RADARE2_GIT
cd radare2
sys/install.sh
cd $INSTDIR

print_status_info "Installing Volatility"
mkdir -p $INSTDIR/volatility
cd $INSTDIR/volatility
for repo in ${VOLATILITY_GIT[*]}; do
	git clone $repo
done
cd $INSTDIR

print_status_info "Installing jd-gui"
mkdir -p $INSTDIR/jd-gui
cd $INSTDIR/jd-gui
wget $JD_GUI -O jd-gui-1.4.0.jar
cd $INSTDIR

print_status_info "Installing dex2jar"
mkdir -p $INSTDIR/dex2jar
cd $INSTDIR/dex2jar
wget $DEX2JAR -O dex-tools-2.1-SNAPSHOT.zip
unzip -o dex-tools-2.1-SNAPSHOT.zip
cd $INSTDIR

print_status_info "Installing cfr"
mkdir -p $INSTDIR/cfr
cd $INSTDIR/cfr
wget $CFR -O cfr-0.140.jar
cd $INSTDIR

print_status_info "Installing pdf-parser"
mkdir -p $INSTDIR/pdf-parser
cd $INSTDIR/pdf-parser
wget $PDF_PARSER -O pdf-parser_V0_7_1.zip
unzip -o pdf-parser_V0_7_1.zip
cd $INSTDIR

print_status_info "Installing yara-rules"
mkdir -p $INSTDIR/yara-rules
cd $INSTDIR/yara-rules
for rule in ${YARA_RULES[*]}; do
	git clone $rule
done
cd $INSTDIR


