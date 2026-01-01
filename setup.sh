#!/bin/bash
# Advanced Network Monitor Installer for Kali Linux

echo "[*] تثبيت مراقب الشبكة المتقدم على Kali Linux"
echo "[*]============================================"

# التحقق من صلاحيات root
if [[ $EUID -ne 0 ]]; then
   echo "[!] يلزم صلاحيات root لتشغيل هذا السكربت"
   echo "[!] استخدم: sudo ./setup.sh"
   exit 1
fi

# تحديث النظام
echo "[*] جاري تحديث النظام..."
apt-get update && apt-get upgrade -y

# تثبيت المكتبات المطلوبة
echo "[*] جاري تثبيت المكتبات الأساسية..."
apt-get install -y \
    python3 \
    python3-pip \
    tshark \
    wireshark \
    net-tools

# تثبيت مكتبات Python
echo "[*] جاري تثبيت مكتبات Python..."
pip3 install --upgrade pip
pip3 install -r requirements.txt

# منح صلاحيات لـ Wireshark
echo "[*] إعداد صلاحيات Wireshark..."
usermod -a -G wireshark $SUDO_USER

# إنشاء رابط تشغيلي
echo "[*] إنشاء رابط تشغيلي..."
chmod +x network_monitor.py
cp network_monitor.py /usr/local/bin/network-monitor

echo "[✔] التثبيت اكتمل بنجاح!"
echo ""
echo "[*] كيفية الاستخدام:"
echo "    1. كـ مستخدم عادي: python3 network_monitor.py"
echo "    2. كـ root (لجميع الميزات): sudo python3 network_monitor.py"
echo "    3. اختصار: network-monitor"
