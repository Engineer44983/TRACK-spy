#!/usr/bin/env python3
"""
Advanced Network Web Monitor - يراقب زيارة المواقع على الشبكة المحلية
"""

import scapy.all as scapy
from scapy.layers import http
import time
import json
import os
import threading
from datetime import datetime
from plyer import notification
import socket
import netifaces
from collections import defaultdict
import signal
import sys

class AdvancedWebMonitor:
    def __init__(self, interface=None, monitor_interval=30):
        """
        تهيئة مراقب الشبكة المتقدم
        """
        self.interface = interface or self.get_default_interface()
        self.monitor_interval = monitor_interval
        self.visited_sites_file = "network_visited_sites.json"
        self.devices_file = "network_devices.json"
        self.target_websites = self.load_target_websites()
        self.visited_sites = self.load_visited_sites()
        self.network_devices = self.load_network_devices()
        self.monitoring = False
        self.captured_packets = []
        self.lock = threading.Lock()
        
        # إعدادات الإشعارات
        self.notification_enabled = True
        
        print(f"تم التهيئة على الواجهة: {self.interface}")
        
    def get_default_interface(self):
        """الحصول على واجهة الشبكة الافتراضية"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        if addr.get('addr') == local_ip:
                            return iface
        except Exception as e:
            print(f"خطأ في تحديد الواجهة: {e}")
        return "eth0"  # قيمة افتراضية
    
    def load_target_websites(self):
        """تحميل قائمة المواقع المستهدفة للمراقبة"""
        target_sites = {
            # مواقع برمجة وتقنية
            "github.com": "GitHub",
            "stackoverflow.com": "Stack Overflow",
            "medium.com": "Medium",
            "dev.to": "Dev Community",
            "realpython.com": "Real Python",
            "css-tricks.com": "CSS Tricks",
            "codepen.io": "CodePen",
            "npmjs.com": "NPM",
            "docker.com": "Docker",
            "kubernetes.io": "Kubernetes",
            "aws.amazon.com": "AWS",
            "azure.microsoft.com": "Azure",
            "cloud.google.com": "Google Cloud",
            "www.mossad.gov.il": "www.cia.gov",
            "codepen.io": "www.sis.gov.uk",
            "www.gip.gov.sa": "NPM",
            "docker.com": "www.dgse.gouv.fr",
            # مواقع اجتماعية
            "linkedin.com": "LinkedIn",
            "twitter.com": "Twitter",
            "facebook.com": "Facebook",
            "instagram.com": "Instagram",
            
            # مواقع تعليمية
            "coursera.org": "Coursera",
            "udemy.com": "Udemy",
            "khanacademy.org": "Khan Academy",
            
            # يمكنك إضافة المزيد حسب حاجتك
        }
        
        # تحميل مواقع مخصصة من ملف إذا وجد
        custom_sites_file = "custom_sites.txt"
        if os.path.exists(custom_sites_file):
            try:
                with open(custom_sites_file, 'r') as f:
                    for line in f:
                        site = line.strip()
                        if site and not site.startswith('#'):
                            domain = site.replace('https://', '').replace('http://', '').split('/')[0]
                            target_sites[domain] = site
                print(f"تم تحميل {len(target_sites)} موقع للمراقبة")
            except Exception as e:
                print(f"خطأ في تحميل المواقع المخصصة: {e}")
        
        return target_sites
    
    def add_custom_site(self, url):
        """إضافة موقع مخصص للمراقبة"""
        domain = url.replace('https://', '').replace('http://', '').split('/')[0]
        self.target_websites[domain] = url
        
        # حفظ في ملف
        custom_sites_file = "custom_sites.txt"
        try:
            with open(custom_sites_file, 'a') as f:
                f.write(f"{url}\n")
            print(f"تم إضافة الموقع: {url}")
            return True
        except Exception as e:
            print(f"خطأ في حفظ الموقع: {e}")
            return False
    
    def load_visited_sites(self):
        """تحميل سجل المواقع التي تمت زيارتها"""
        if os.path.exists(self.visited_sites_file):
            try:
                with open(self.visited_sites_file, 'r') as f:
                    return json.load(f)
            except:
                return defaultdict(dict)
        return defaultdict(dict)
    
    def load_network_devices(self):
        """تحميل سجل الأجهزة المعروفة"""
        if os.path.exists(self.devices_file):
            try:
                with open(self.devices_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def save_data(self):
        """حفظ جميع البيانات"""
        with self.lock:
            try:
                # حفظ المواقع
                with open(self.visited_sites_file, 'w') as f:
                    json.dump(self.visited_sites, f, indent=2)
                
                # حفظ الأجهزة
                with open(self.devices_file, 'w') as f:
                    json.dump(self.network_devices, f, indent=2)
            except Exception as e:
                print(f"خطأ في حفظ البيانات: {e}")
    
    def send_notification(self, title, message):
        """إرسال إشعار للمستخدم"""
        if self.notification_enabled:
            try:
                notification.notify(
                    title=title,
                    message=message,
                    timeout=10,
                    app_name="Network Web Monitor"
                )
                print(f"📢 {title}: {message}")
            except Exception as e:
                print(f"تنبيه: {title} - {message}")
    
    def scan_network_devices(self, ip_range=None):
        """مسح الشبكة للكشف عن الأجهزة المتصلة"""
        if not ip_range:
            # محاولة تخمين نطاق IP تلقائياً
            try:
                for iface in netifaces.interfaces():
                    if iface == self.interface:
                        addrs = netifaces.ifaddresses(iface)
                        if netifaces.AF_INET in addrs:
                            for addr in addrs[netifaces.AF_INET]:
                                ip = addr.get('addr')
                                if ip and ip != '127.0.0.1':
                                    # استخراج نطاق الشبكة
                                    parts = ip.split('.')
                                    ip_range = f"{parts[0]}.{parts[1]}.{parts[2]}.1/24"
                                    break
            except:
                ip_range = "192.168.1.1/24"
        
        devices = {}
        
        try:
            print(f"جاري مسح الشبكة: {ip_range}")
            arp_request = scapy.ARP(pdst=ip_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            
            answered_list = scapy.srp(
                arp_request_broadcast, 
                timeout=3, 
                verbose=False,
                iface=self.interface
            )[0]
            
            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc
                
                # محاولة الحصول على اسم الجهاز
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = "جهاز غير معروف"
                
                devices[ip] = {
                    'mac': mac,
                    'hostname': hostname,
                    'last_seen': datetime.now().isoformat(),
                    'vendor': self.get_vendor_from_mac(mac)
                }
                
                # تحديث سجل الأجهزة
                if ip not in self.network_devices:
                    self.network_devices[ip] = devices[ip]
                    print(f"🚀 اكتشاف جهاز جديد: {ip} ({hostname})")
                
        except Exception as e:
            print(f"خطأ في مسح الشبكة: {e}")
            
        return devices
    
    def get_vendor_from_mac(self, mac):
        """الحصول على معلومات الشركة المصنعة من عنوان MAC"""
        # يمكن تحسين هذا الجزء بقاعدة بيانات OUI
        vendors = {
            '00:0c:29': 'VMware',
            '00:50:56': 'VMware',
            '00:1a:4b': 'Apple',
            '00:23:12': 'Apple',
            '00:25:bc': 'Apple',
            'bc:30:7d': 'Apple',
            'a4:5e:60': 'Apple',
            '28:cf:e9': 'Apple',
            '00:1d:7e': 'Samsung',
            '00:26:5a': 'Samsung',
            '00:0f:b0': 'Dell',
            '00:14:22': 'Dell',
            '00:18:8b': 'Dell',
            '00:1c:c4': 'HP',
            '00:21:5a': 'HP',
            '00:26:b9': 'HP',
        }
        
        for prefix, vendor in vendors.items():
            if mac.lower().startswith(prefix.lower()):
                return vendor
        return "غير معروف"
    
    def process_packet(self, packet):
        """معالجة الحزمة الملتقطة"""
        try:
            # التحقق من وجود طبقة HTTP
            if packet.haslayer(http.HTTPRequest):
                # استخراج معلومات HTTP
                host = packet[http.HTTPRequest].Host.decode()
                path = packet[http.HTTPRequest].Path.decode()
                full_url = f"http://{host}{path}"
                
                # استخراج عنوان IP المصدر
                src_ip = packet[scapy.IP].src
                
                # التحقق إذا كان الموقع مستهدفاً
                for domain, site_name in self.target_websites.items():
                    if domain in host:
                        self.handle_detected_site(host, src_ip, full_url, site_name)
                        break
                        
            # التحقق من حزم DNS
            elif packet.haslayer(scapy.DNSQR):
                # استخراج اسم النطاق المطلوب
                dns_query = packet[scapy.DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                src_ip = packet[scapy.IP].src
                
                # التحقق إذا كان الموقع مستهدفاً
                for domain, site_name in self.target_websites.items():
                    if domain in dns_query:
                        full_url = f"https://{dns_query}"
                        self.handle_detected_site(dns_query, src_ip, full_url, site_name)
                        break
                        
        except Exception as e:
            # تجاهل الأخطاء في المعالجة
            pass
    
    def handle_detected_site(self, domain, src_ip, full_url, site_name):
        """معالجة الموقع المكتشف"""
        with self.lock:
            current_time = datetime.now().isoformat()
            device_info = self.network_devices.get(src_ip, {})
            device_name = device_info.get('hostname', 'جهاز غير معروف')
            
            # تسجيل الزيارة
            if domain not in self.visited_sites:
                self.visited_sites[domain] = {
                    'site_name': site_name,
                    'first_visited': current_time,
                    'last_visited': current_time,
                    'visits': 1,
                    'visitors': [src_ip]
                }
            else:
                self.visited_sites[domain]['last_visited'] = current_time
                self.visited_sites[domain]['visits'] += 1
                if src_ip not in self.visited_sites[domain]['visitors']:
                    self.visited_sites[domain]['visitors'].append(src_ip)
            
            # إرسال إشعار
            notification_msg = f"📍 {device_name}\n🌐 {site_name}\n🔗 {domain}\n🕒 {datetime.now().strftime('%H:%M:%S')}"
            
            self.send_notification(
                "🚨 زيارة موقع مستهدف",
                notification_msg
            )
            
            # طباعة في السطر
            print(f"\n{'='*60}")
            print(f"🚨 زيارة موقع مستهدف!")
            print(f"🕒 الوقت: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"💻 الجهاز: {device_name} ({src_ip})")
            print(f"🌐 الموقع: {site_name}")
            print(f"🔗 الرابط: {full_url}")
            print(f"{'='*60}\n")
            
            # حفظ البيانات بشكل فوري
            self.save_data()
    
    def start_capture(self):
        """بدء التقاط حزم الشبكة"""
        print("🎯 بدء مراقبة حركة الشبكة...")
        print("📡 جاري الاستماع لطلبات HTTP وDNS...")
        
        # تصفية لمراقبة HTTP و DNS
        filter_str = "tcp port 80 or tcp port 443 or udp port 53"
        
        try:
            scapy.sniff(
                prn=self.process_packet,
                filter=filter_str,
                store=False,
                iface=self.interface
            )
        except Exception as e:
            print(f"خطأ في التقاط الحزم: {e}")
            self.monitoring = False
    
    def start_monitoring(self):
        """بدء المراقبة الشاملة"""
        self.monitoring = True
        
        # بدء مسح الشبكة أولاً
        print("🔍 جاري مسح الشبكة للأجهزة المتصلة...")
        devices = self.scan_network_devices()
        print(f"✅ تم اكتشاف {len(devices)} جهاز على الشبكة")
        
        # بدء التقاط الحزم في thread منفصل
        capture_thread = threading.Thread(target=self.start_capture, daemon=True)
        capture_thread.start()
        
        # حلقة المراقبة الرئيسية
        try:
            scan_counter = 0
            while self.monitoring:
                time.sleep(self.monitor_interval)
                scan_counter += 1
                
                # مسح دوري للشبكة كل 5 دقائق
                if scan_counter >= 10:  # كل 5 دقائق (30 ثانية × 10)
                    print("\n🔄 جاري تحديث قائمة الأجهزة...")
                    self.scan_network_devices()
                    scan_counter = 0
                    
                    # عرض إحصائيات
                    self.show_statistics()
                
        except KeyboardInterrupt:
            print("\n\n🛑 توقف المراقبة...")
        finally:
            self.monitoring = False
            self.save_data()
            print("💾 تم حفظ جميع البيانات")
    
    def show_statistics(self):
        """عرض إحصائيات المراقبة"""
        print("\n" + "="*60)
        print("📊 إحصائيات المراقبة:")
        print("="*60)
        print(f"عدد الأجهزة المعروفة: {len(self.network_devices)}")
        print(f"عدد المواقع المستهدفة: {len(self.target_websites)}")
        print(f"عدد المواقع التي تمت زيارتها: {len(self.visited_sites)}")
        
        if self.visited_sites:
            print("\n📈 المواقع الأكثر زيارة:")
            sorted_sites = sorted(self.visited_sites.items(), 
                                 key=lambda x: x[1].get('visits', 0), 
                                 reverse=True)[:5]
            for domain, info in sorted_sites:
                print(f"  {info.get('site_name', domain)}: {info.get('visits', 0)} زيارة")
        print("="*60 + "\n")
    
    def interactive_menu(self):
        """قائمة تفاعلية للمستخدم"""
        while True:
            print("\n" + "="*60)
            print("🔧 قائمة مراقبة الشبكة المتقدمة")
            print("="*60)
            print("1. بدء المراقبة")
            print("2. إضافة موقع للمراقبة")
            print("3. عرض المواقع المستهدفة")
            print("4. عرض المواقع التي تمت زيارتها")
            print("5. عرض الأجهزة المتصلة")
            print("6. عرض الإحصائيات")
            print("7. إعدادات الإشعارات")
            print("8. حفظ البيانات")
            print("9. الخروج")
            print("="*60)
            
            choice = input("اختر الخيار [1-9]: ").strip()
            
            if choice == "1":
                print("\n🎯 بدء المراقبة...")
                print("ملاحظة: قد تحتاج لتشغيل السكربت بصلاحيات مسؤول")
                self.start_monitoring()
                
            elif choice == "2":
                url = input("أدخل رابط الموقع (مثال: https://example.com): ").strip()
                if url:
                    self.add_custom_site(url)
                
            elif choice == "3":
                print("\n📋 المواقع المستهدفة للمراقبة:")
                for domain, name in self.target_websites.items():
                    print(f"  • {name}: {domain}")
                
            elif choice == "4":
                print("\n📖 المواقع التي تمت زيارتها:")
                if not self.visited_sites:
                    print("  لم يتم زيارة أي موقع مستهدف بعد")
                else:
                    for domain, info in self.visited_sites.items():
                        last_visit = info.get('last_visited', 'غير معروف')
                        visits = info.get('visits', 0)
                        print(f"  • {info.get('site_name', domain)}")
                        print(f"    🔢 عدد الزيارات: {visits}")
                        print(f"    🕒 آخر زيارة: {last_visit[:19]}")
                        print(f"    👥 الزوار: {len(info.get('visitors', []))} جهاز")
                        print()
                
            elif choice == "5":
                print("\n💻 الأجهزة المتصلة على الشبكة:")
                devices = self.scan_network_devices()
                for ip, info in devices.items():
                    print(f"  • {info.get('hostname', 'غير معروف')}")
                    print(f"    📍 IP: {ip}")
                    print(f"    🔑 MAC: {info.get('mac', 'غير معروف')}")
                    print(f"    🏭 الشركة: {info.get('vendor', 'غير معروف')}")
                    print()
                
            elif choice == "6":
                self.show_statistics()
                
            elif choice == "7":
                self.notification_enabled = not self.notification_enabled
                status = "مفعلة" if self.notification_enabled else "معطلة"
                print(f"\n🔔 الإشعارات الآن {status}")
                
            elif choice == "8":
                self.save_data()
                print("💾 تم حفظ البيانات بنجاح")
                
            elif choice == "9":
                print("\n👋 مع السلامة!")
                self.save_data()
                break
                
            else:
                print("❌ اختيار غير صحيح")

def signal_handler(sig, frame):
    """معالج إشارة الإنتهاء"""
    print("\n\n🛑 تم إيقاف البرنامج")
    sys.exit(0)

def main():
    """الدالة الرئيسية"""
    # تسجيل معالج الإشارات
    signal.signal(signal.SIGINT, signal_handler)
    
    print("="*60)
    print("🚀 مراقب الشبكة المتقدم - Advanced Network Web Monitor")
    print("="*60)
    print("👨‍💻 المطور: مبرمج تقني")
    print("📅 الإصدار: 2.0")
    print("="*60)
    
    # طلب صلاحيات root إذا لزم الأمر
    if os.name != 'nt' and os.geteuid() != 0:
        print("\n⚠️  تحذير: لمراقبة الشبكة بشكل كامل، يفضل تشغيل البرنامج بصلاحيات مسؤول")
        print("   يمكنك استخدام: sudo python3 script.py")
        print("   أو تشغيله كمستخدم عادي مع صلاحيات محدودة")
        print("="*60)
    
    # إنشاء كائن المراقبة
    try:
        monitor = AdvancedWebMonitor(monitor_interval=30)
        
        # عرض الإعدادات الأولية
        print(f"\n⚙️  الإعدادات:")
        print(f"  واجهة الشبكة: {monitor.interface}")
        print(f"  فترة المسح: كل 30 ثانية")
        print(f"  عدد المواقع المستهدفة: {len(monitor.target_websites)}")
        
        # بدء القائمة التفاعلية
        monitor.interactive_menu()
        
    except Exception as e:
        print(f"❌ خطأ في تشغيل البرنامج: {e}")
        print("تأكد من تثبيت المكتبات المطلوبة:")
        print("pip install scapy plyer netifaces")

if __name__ == "__main__":
    # التحقق من المكتبات المطلوبة
    try:
        import scapy.all
        from scapy.layers import http
        from plyer import notification
        import netifaces
    except ImportError as e:
        print(f"❌ مكتبة مفقودة: {e}")
        print("📦 جاري تثبيت المكتبات المطلوبة...")
        print("   قم بتشغيل: pip install scapy plyer netifaces")
        exit(1)
    
    # إنشاء ملف للمواقع المخصصة إذا لم يكن موجوداً
    if not os.path.exists("custom_sites.txt"):
        with open("custom_sites.txt", "w") as f:
            f.write("# قائمة المواقع المخصصة للمراقبة\n")
            f.write("# أضف موقعاً جديداً في كل سطر\n")
            f.write("# مثال:\n")
            f.write("# https://example.com\n")
            f.write("# http://test.com\n")
    
    # تشغيل البرنامج
    main()
