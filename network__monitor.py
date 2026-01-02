#!/usr/bin/env python3
"""
أداة مراقبة المواقع التي يزورها الآخرون على نفس الشبكة
Local Network HTTP Traffic Monitor
ملاحظة: للاستخدام القانوني فقط (اختبار اختراق بموافقة، مراقبة شبكتك الخاصة)
"""

import scapy.all as scapy
from scapy.layers import http
import argparse
import sys
from datetime import datetime
import signal
import os

class NetworkMonitor:
    def __init__(self, interface=None, output_file=None):
        self.interface = interface
        self.output_file = output_file
        self.running = True
        
        # ألوان للواجهة
        self.RED = "\033[91m"
        self.GREEN = "\033[92m"
        self.YELLOW = "\033[93m"
        self.BLUE = "\033[94m"
        self.RESET = "\033[0m"
        
        # إدارة الإغلاق الأنظف
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        print(f"\n{self.YELLOW}[!] إيقاف المراقبة...{self.RESET}")
        self.running = False
    
    def get_arguments(self):
        parser = argparse.ArgumentParser(description='أداة مراقبة حركة HTTP على الشبكة المحلية')
        parser.add_argument('-i', '--interface', dest='interface', 
                          help='واجهة الشبكة للمراقبة (مثال: eth0, wlan0)')
        parser.add_argument('-o', '--output', dest='output_file',
                          help='حفظ النتائج في ملف')
        
        args = parser.parse_args()
        
        if not args.interface:
            self.show_interfaces()
            args.interface = input(f"{self.BLUE}[?] أدخل اسم الواجهة: {self.RESET}")
        
        return args
    
    def show_interfaces(self):
        """عرض واجهات الشبكة المتاحة"""
        print(f"{self.BLUE}[*] الواجهات المتاحة:{self.RESET}")
        os.system("ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print $2}'")
    
    def process_packet(self, packet):
        """معالجة الحزم واستخراج معلومات HTTP"""
        try:
            if packet.haslayer(http.HTTPRequest):
                # استخراج عنوان IP المصدر
                src_ip = packet[scapy.IP].src
                
                # استخراج اسم المضيف (الموقع)
                host = packet[http.HTTPRequest].Host.decode('utf-8') if packet[http.HTTPRequest].Host else "Unknown"
                
                # استخراج المسار
                path = packet[http.HTTPRequest].Path.decode('utf-8') if packet[http.HTTPRequest].Path else "/"
                
                # استخراج وكيل المستخدم
                user_agent = ""
                if packet.haslayer(scapy.Raw):
                    load = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                    if 'User-Agent' in load:
                        user_agent = load.split('User-Agent: ')[1].split('\r\n')[0]
                
                # عرض المعلومات
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.display_info(timestamp, src_ip, host, path, user_agent)
                
                # حفظ في الملف إذا طلب
                if self.output_file:
                    self.save_to_file(timestamp, src_ip, host, path, user_agent)
        
        except Exception as e:
            pass  # تجاهل الحزم التي لا يمكن معالجتها
    
    def display_info(self, timestamp, src_ip, host, path, user_agent):
        """عرض المعلومات بشكل منسق"""
        print(f"\n{self.GREEN}[+] {timestamp}{self.RESET}")
        print(f"{self.BLUE}   IP المصدر: {self.RESET}{src_ip}")
        print(f"{self.BLUE}   الموقع: {self.RESET}{host}{path}")
        
        if user_agent:
            print(f"{self.BLUE}   المتصفح: {self.RESET}{user_agent[:80]}...")
        
        print(f"{'-'*60}")
    
    def save_to_file(self, timestamp, src_ip, host, path, user_agent):
        """حفظ النتائج في ملف"""
        with open(self.output_file, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}]\n")
            f.write(f"IP المصدر: {src_ip}\n")
            f.write(f"الموقع: {host}{path}\n")
            f.write(f"المتصفح: {user_agent}\n")
            f.write("-" * 50 + "\n\n")
    
    def start_monitoring(self):
        """بدء المراقبة"""
        print(f"{self.YELLOW}[*] بدء مراقبة حركة HTTP على الواجهة: {self.interface}{self.RESET}")
        print(f"{self.YELLOW}[*] اضغط Ctrl+C للإيقاف{self.RESET}")
        print(f"{'='*60}\n")
        
        try:
            # بدء التقاط الحزم
            scapy.sniff(
                iface=self.interface,
                store=False,
                prn=self.process_packet,
                filter="tcp port 80 or tcp port 443"
            )
        except PermissionError:
            print(f"{self.RED}[!] تحتاج إلى صلاحيات root!{self.RESET}")
            print(f"{self.YELLOW}[*] جرب: sudo python3 {sys.argv[0]} -i {self.interface}{self.RESET}")
            sys.exit(1)
        except Exception as e:
            print(f"{self.RED}[!] خطأ: {e}{self.RESET}")

def check_dependencies():
    """فحص التبعيات المطلوبة"""
    try:
        import scapy.all
        print("[✓] مكتبة scapy مثبتة")
        return True
    except ImportError:
        print("[✗] مكتبة scapy غير مثبتة")
        return False

def install_dependencies():
    """تثبيت التبعيات المطلوبة"""
    print("\n[*] تثبيت التبعيات المطلوبة...")
    os.system("sudo apt update")
    os.system("sudo apt install -y python3-pip")
    os.system("sudo pip3 install scapy")

def main():
    print("""
    ███╗   ███╗ ██████╗ ███╗   ██╗██╗████████╗ ██████╗ ██████╗ 
    ████╗ ████║██╔═══██╗████╗  ██║██║╚══██╔══╝██╔═══██╗██╔══██╗
    ██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║   ██║   ██║██████╔╝
    ██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║   ██║   ██║██╔══██╗
    ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║   ██║   ╚██████╔╝██║  ██║
    ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
    
    أداة مراقبة حركة HTTP على الشبكة المحلية
    الإصدار: 1.0 | للاستخدام القانوني فقط
    """)
    
    # فحص التبعيات
    if not check_dependencies():
        answer = input("\n[?] هل تريد تثبيت التبعيات تلقائياً؟ (y/n): ")
        if answer.lower() == 'y':
            install_dependencies()
        else:
            print("[!] يجب تثبيت scapy أولاً:")
            print("    sudo pip3 install scapy")
            sys.exit(1)
    
    # إنشاء كائن المراقبة
    monitor = NetworkMonitor()
    
    # الحصول على المدخلات
    args = monitor.get_arguments()
    monitor.interface = args.interface
    monitor.output_file = args.output_file
    
    # بدء المراقبة (يحتاج صلاحيات root)
    if os.geteuid() != 0:
        print("\n[!] هذه الأداة تحتاج صلاحيات root للعمل")
        print("[*] جرب: sudo python3 " + sys.argv[0] + " -i " + monitor.interface)
        sys.exit(1)
    
    monitor.start_monitoring()

if __name__ == "__main__":
    main()
