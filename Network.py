#!/usr/bin/env python3
"""
Advanced Network Web Monitor - يراقب زيارة المواقع على الشبكة المحلية
مصمم خصيصاً لـ Kali Linux
"""

import sys
import time
import json
import os
import threading
from datetime import datetime
import socket
import netifaces
from collections import defaultdict
import signal
import subprocess
import platform

# استيراد Scapy بطريقة متوافقة مع Kali
try:
    from scapy.all import ARP, Ether, srp, sniff, IP, DNS, DNSQR
    from scapy.layers import http
    SCAPY_AVAILABLE = True
except ImportError:
    print("❌ خطأ: Scapy غير مثبت!")
    print("📦 جاري تثبيت Scapy...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy"])
        from scapy.all import ARP, Ether, srp, sniff, IP, DNS, DNSQR
        from scapy.layers import http
        SCAPY_AVAILABLE = True
        print("✅ تم تثبيت Scapy بنجاح")
    except:
        SCAPY_AVAILABLE = False
        print("❌ فشل تثبيت Scapy")

# استيراد المكتبات الأخرى
try:
    from plyer import notification
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False
    print("⚠️  المكتبة plyer غير مثبتة - الإشعارات معطلة")

class AdvancedWebMonitor:
    def __init__(self, interface=None, monitor_interval=30):
        """
        تهيئة مراقب الشبكة المتقدم
        """
        if not SCAPY_AVAILABLE:
            print("❌ لا يمكن تشغيل السكربت بدون Scapy")
            sys.exit(1)
            
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
        self.notification_enabled = PLYER_AVAILABLE
        
        print(f"✅ تم التهيئة على الواجهة: {self.interface}")
        print(f"📡 نظام التشغيل: {platform.system()} {platform.release()}")
        
    def get_default_interface(self):
        """الحصول على واجهة الشبكة الافتراضية"""
        try:
            # محاولة استخدام iproute2 على Linux
            if platform.system() == "Linux":
                try:
                    result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if 'dev' in line:
                                parts = line.split()
                                if len(parts) > 4:
                                    return parts[4]
                except:
                    pass
            
            # طريقة احتياطية
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            for iface in netifaces.interfaces():
                if iface.startswith(('lo', 'docker', 'br-', 'veth')):
                    continue
                    
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        if addr.get('addr') == local_ip:
                            return iface
        except Exception as e:
            print(f"⚠️  تحذير في تحديد الواجهة: {e}")
        
        # محاولة اكتشاف واجهات الشبكة المتاحة
        print("\n🔍 الواجهات المتاحة:")
        try:
            for iface in netifaces.interfaces():
                if not iface.startswith('lo'):
                    print(f"  - {iface}")
                    
                    # اختبار الواجهة
                    try:
                        addrs = netifaces.ifaddresses(iface)
                        if netifaces.AF_INET in addrs:
                            for addr in addrs[netifaces.AF_INET]:
                                ip = addr.get('addr', 'لا يوجد IP')
                                print(f"    📍 IP: {ip}")
                                if ip and ip != '127.0.0.1':
                                    return iface
                    except:
                        continue
        except:
            pass
            
        return "eth0"  # قيمة افتراضية
    
    def load_target_websites(self):
        """تحميل قائمة المواقع المستهدفة للمراقبة"""
        target_sites = {
            # مواقع برمجة وتقنية
            "https://www.mossad.gov.il/en": "GitHub",
            "https://www.cia.gov/": "Stack Overflow",
            "gitlab.com": "GitLab",
            "bitbucket.org": "Bitbucket",
            "medium.com": "Medium",
            "dev.to": "Dev Community",
            "realpython.com": "Real Python",
            "css-tricks.com": "CSS Tricks",
            "codepen.io": "CodePen",
            "w3schools.com": "W3Schools",
            "npmjs.com": "NPM",
            "docker.com": "Docker",
            "kubernetes.io": "Kubernetes",
            
            # مواقع تعليمية
            "coursera.org": "Coursera",
            "udemy.com": "Udemy",
            "edx.org": "edX",
            "khanacademy.org": "Khan Academy",
            
            # مواقع تواصل اجتماعي
            "linkedin.com": "LinkedIn",
            "twitter.com": "Twitter/X",
            "facebook.com": "Facebook",
            "instagram.com": "Instagram",
            "reddit.com": "Reddit",
            
            # مواقع أخبار تقنية
            "techcrunch.com": "TechCrunch",
            "theverge.com": "The Verge",
            "wired.com": "Wired",
            "arstechnica.com": "Ars Technica",
        }
        
        # تحميل مواقع مخصصة من ملف إذا وجد
        custom_sites_file = "custom_sites.txt"
        if os.path.exists(custom_sites_file):
            try:
                with open(custom_sites_file, 'r') as f:
                    for line in f:
                        site = line.strip()
                        if site and not site.startswith('#'):
                            # استخراج النطاق الأساسي
                            domain = site.replace('https://', '').replace('http://', '').split('/')[0]
                            target_sites[domain] = site
                print(f"✅ تم تحميل {len(target_sites)} موقع للمراقبة")
            except Exception as e:
                print(f"⚠️  خطأ في تحميل المواقع المخصصة: {e}")
        
        return target_sites
    
    def add_custom_site(self, url):
        """إضافة موقع مخصص للمراقبة"""
        domain = url.replace('https://', '').replace('http://', '').split('/')[0]
        if domain not in self.target_websites:
            self.target_websites[domain] = url
            
            # حفظ في ملف
            custom_sites_file = "custom_sites.txt"
            try:
                with open(custom_sites_file, 'a') as f:
                    f.write(f"{url}\n")
                print(f"✅ تم إضافة الموقع: {url}")
                return True
            except Exception as e:
                print(f"❌ خطأ في حفظ الموقع: {e}")
                return False
        else:
            print(f"⚠️  الموقع {domain} موجود بالفعل في القائمة")
            return True
    
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
                    json.dump(self.visited_sites, f, indent=2, ensure_ascii=False)
                
                # حفظ الأجهزة
                with open(self.devices_file, 'w') as f:
                    json.dump(self.network_devices, f, indent=2, ensure_ascii=False)
                    
                return True
            except Exception as e:
                print(f"❌ خطأ في حفظ البيانات: {e}")
                return False
    
    def send_notification(self, title, message):
        """إرسال إشعار للمستخدم"""
        if self.notification_enabled and PLYER_AVAILABLE:
            try:
                notification.notify(
                    title=title,
                    message=message,
                    timeout=10,
                    app_name="Network Web Monitor"
                )
                print(f"📢 {title}: {message}")
            except Exception as e:
                print(f"📢 {title}: {message}")
        else:
            print(f"📢 {title}: {message}")
    
    def scan_network_devices(self, ip_range=None):
        """مسح الشبكة للكشف عن الأجهزة المتصلة"""
        if not SCAPY_AVAILABLE:
            print("❌ Scapy غير متوفر - لا يمكن مسح الشبكة")
            return {}
            
        if not ip_range:
            # محاولة اكتشاف نطاق IP تلقائياً
            ip_range = self.detect_network_range()
        
        devices = {}
        
        try:
            print(f"🔍 جاري مسح الشبكة: {ip_range}")
            print(f"📡 الواجهة: {self.interface}")
            
            # إنشاء حزمة ARP
            arp_request = ARP(pdst=ip_range)
            
            # إنشاء إطار Ethernet
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            
            # تجميع الحزمة
            arp_request_broadcast = broadcast/arp_request
            
            # إرسال واستقبال الحزم
            answered_list = srp(
                arp_request_broadcast, 
                timeout=3, 
                verbose=False,
                iface=self.interface,
                inter=0.1
            )[0]
            
            print(f"✅ تم استلام ردود من {len(answered_list)} جهاز")
            
            for sent, received in answered_list:
                ip = received.psrc
                mac = received.hwsrc
                
                # محاولة الحصول على اسم الجهاز
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = "جهاز غير معروف"
                
                vendor = self.get_vendor_from_mac(mac)
                
                devices[ip] = {
                    'mac': mac,
                    'hostname': hostname,
                    'last_seen': datetime.now().isoformat(),
                    'vendor': vendor,
                    'status': 'active'
                }
                
                # تحديث سجل الأجهزة
                if ip not in self.network_devices:
                    self.network_devices[ip] = devices[ip]
                    print(f"🚀 اكتشاف جهاز جديد: {hostname} ({ip}) - {vendor}")
                
        except PermissionError:
            print("❌ خطأ في الصلاحيات! جرب تشغيل السكربت بـ sudo:")
            print("   sudo python3 script.py")
            return {}
        except Exception as e:
            print(f"❌ خطأ في مسح الشبكة: {e}")
            print(f"   نوع الخطأ: {type(e).__name__}")
            
        return devices
    
    def detect_network_range(self):
        """اكتشاف نطاق الشبكة تلقائياً"""
        try:
            # الحصول على IP المحلي
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # استخراج نطاق الشبكة (افتراض /24)
            parts = local_ip.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                
        except:
            pass
            
        # قيم افتراضية شائعة
        common_ranges = [
            "192.168.1.0/24",
            "192.168.0.0/24",
            "10.0.0.0/24",
            "172.16.0.0/24"
        ]
        
        print("🔍 جرب نطاقات IP التالية:")
        for i, ip_range in enumerate(common_ranges, 1):
            print(f"  {i}. {ip_range}")
            
        # تجربة النطاقات بشكل تلقائي
        for ip_range in common_ranges:
            try:
                print(f"\n🔍 جرب {ip_range}...")
                arp_request = ARP(pdst=ip_range)
                broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast/arp_request
                
                answered = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
                if len(answered) > 0:
                    print(f"✅ نجح: {ip_range}")
                    return ip_range
            except:
                continue
                
        return "192.168.1.0/24"  # افتراضي
    
    def get_vendor_from_mac(self, mac):
        """الحصول على معلومات الشركة المصنعة من عنوان MAC"""
        # أول 3 بايت (OUI)
        oui = mac[:8].upper().replace(':', '')
        
        # قاعدة بيانات OUI مبسطة
        vendors = {
            '000C29': 'VMware',
            '005056': 'VMware',
            '001A4B': 'Apple',
            '002312': 'Apple',
            '0025BC': 'Apple',
            'B8307D': 'Apple',
            'A45E60': 'Apple',
            '28CFE9': 'Apple',
            '001D7E': 'Samsung',
            '00265A': 'Samsung',
            '000FB0': 'Dell',
            '001422': 'Dell',
            '00188B': 'Dell',
            '001CC4': 'HP',
            '00215A': 'HP',
            '0026B9': 'HP',
            '0015C1': 'TP-Link',
            '001E46': 'TP-Link',
            '0021E9': 'TP-Link',
            'C4E984': 'TP-Link',
            '001E8A': 'Cisco',
            '0021A8': 'Cisco',
            '005073': 'Cisco',
        }
        
        for prefix, vendor in vendors.items():
            if oui.startswith(prefix):
                return vendor
        return "غير معروف"
    
    def process_packet(self, packet):
        """معالجة الحزمة الملتقطة"""
        try:
            # التحقق من وجود طبقة IP
            if not packet.haslayer(IP):
                return
            
            src_ip = packet[IP].src
            
            # 1. تحليل حزم HTTP
            if packet.haslayer(http.HTTPRequest):
                try:
                    host = packet[http.HTTPRequest].Host.decode('utf-8', errors='ignore')
                    if host:
                        self.check_and_notify(host, src_ip, "HTTP")
                except:
                    pass
            
            # 2. تحليل حزم DNS
            elif packet.haslayer(DNSQR):
                try:
                    dns_query = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                    if dns_query:
                        self.check_and_notify(dns_query, src_ip, "DNS")
                except:
                    pass
                    
            # 3. تحليل حزم TLS/SSL (SNI)
            elif packet.haslayer('Raw'):
                try:
                    raw_data = bytes(packet['Raw'])
                    # البحث عن SNI في حزم TLS Client Hello
                    if b'\x00\x00' in raw_data and b'\x00\x16' in raw_data:
                        # هذا تبسيط - في الواقع تحتاج تحليل TLS معقد
                        pass
                except:
                    pass
                    
        except Exception as e:
            # تجاهل الأخطاء البسيطة
            pass
    
    def check_and_notify(self, domain, src_ip, protocol):
        """التحقق من الموقع وإرسال الإشعار"""
        with self.lock:
            for target_domain, site_name in self.target_websites.items():
                if target_domain in domain:
                    current_time = datetime.now()
                    time_str = current_time.strftime('%Y-%m-%d %H:%M:%S')
                    
                    # الحصول على معلومات الجهاز
                    device_info = self.network_devices.get(src_ip, {})
                    device_name = device_info.get('hostname', src_ip)
                    vendor = device_info.get('vendor', 'غير معروف')
                    
                    # تسجيل الزيارة
                    if domain not in self.visited_sites:
                        self.visited_sites[domain] = {
                            'site_name': site_name,
                            'first_visited': current_time.isoformat(),
                            'last_visited': current_time.isoformat(),
                            'visits': 1,
                            'visitors': [src_ip],
                            'protocol': protocol
                        }
                    else:
                        self.visited_sites[domain]['last_visited'] = current_time.isoformat()
                        self.visited_sites[domain]['visits'] += 1
                        if src_ip not in self.visited_sites[domain]['visitors']:
                            self.visited_sites[domain]['visitors'].append(src_ip)
                    
                    # إعداد رسالة الإشعار
                    notification_msg = f"""
📍 الجهاز: {device_name} ({src_ip})
🏭 الشركة: {vendor}
🌐 الموقع: {site_name}
🔗 النطاق: {domain}
📡 البروتوكول: {protocol}
🕒 الوقت: {time_str}
                    """.strip()
                    
                    # إرسال الإشعار
                    self.send_notification("🚨 زيارة موقع مستهدف", notification_msg)
                    
                    # طباعة في السجل
                    print(f"\n{'='*60}")
                    print("🚨 زيارة موقع مستهدف!")
                    print(f"💻 الجهاز: {device_name} ({src_ip})")
                    print(f"🌐 الموقع: {site_name}")
                    print(f"🔗 النطاق: {domain}")
                    print(f"📡 البروتوكول: {protocol}")
                    print(f"🕒 الوقت: {time_str}")
                    print(f"{'='*60}")
                    
                    # حفظ البيانات
                    self.save_data()
                    break
    
    def start_capture(self):
        """بدء التقاط حزم الشبكة"""
        print("🎯 بدء مراقبة حركة الشبكة...")
        print("📡 جاري الاستماع لطلبات HTTP وDNS...")
        print("⚠️  اضغط Ctrl+C لإيقاف المراقبة\n")
        
        try:
            # تصفية المراقبة
            filter_str = "tcp port 80 or tcp port 443 or udp port 53"
            
            # بدء الالتقاط
            sniff(
                prn=self.process_packet,
                filter=filter_str,
                store=False,
                iface=self.interface,
                stop_filter=lambda x: not self.monitoring
            )
            
        except PermissionError:
            print("❌ خطأ في الصلاحيات!")
            print("🔑 جرب تشغيل السكربت بـ sudo:")
            print("   sudo python3 script.py")
            self.monitoring = False
        except Exception as e:
            print(f"❌ خطأ في التقاط الحزم: {type(e).__name__}")
            print(f"   التفاصيل: {e}")
            self.monitoring = False
    
    def start_monitoring(self):
        """بدء المراقبة الشاملة"""
        if not SCAPY_AVAILABLE:
            print("❌ لا يمكن بدء المراقبة بدون Scapy")
            return
        
        self.monitoring = True
        
        # بدء مسح الشبكة أولاً
        print("🔍 جاري مسح الشبكة للأجهزة المتصلة...")
        devices = self.scan_network_devices()
        
        if not devices:
            print("⚠️  لم يتم اكتشاف أجهزة. تأكد من:")
            print("   1. أن الجهاز متصل بالشبكة")
            print("   2. أن نطاق IP صحيح")
            print("   3. جرب نطاق IP مختلف")
            
            # طلب نطاق IP يدوياً
            ip_range = input("أدخل نطاق IP (مثال: 192.168.1.0/24 أو اضغط Enter للتخطي): ").strip()
            if ip_range:
                devices = self.scan_network_devices(ip_range)
        
        print(f"✅ تم اكتشاف {len(devices)} جهاز على الشبكة")
        
        # بدء التقاط الحزم في thread منفصل
        capture_thread = threading.Thread(target=self.start_capture, daemon=True)
        capture_thread.start()
        
        # حلقة المراقبة الرئيسية
        try:
            scan_counter = 0
            print("\n📊 جاري المراقبة...")
            
            while self.monitoring:
                time.sleep(1)  # فحص كل ثانية
                scan_counter += 1
                
                # مسح دوري للشبكة كل 5 دقائق
                if scan_counter >= self.monitor_interval * 10:  # كل 5 دقائق
                    print("\n🔄 جاري تحديث قائمة الأجهزة...")
                    self.scan_network_devices()
                    scan_counter = 0
                    
                    # عرض إحصائيات كل 10 دقائق
                    if scan_counter == 0:
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
        print(f"🔢 عدد الأجهزة المعروفة: {len(self.network_devices)}")
        print(f"🎯 عدد المواقع المستهدفة: {len(self.target_websites)}")
        print(f"📈 عدد المواقع التي تمت زيارتها: {len(self.visited_sites)}")
        
        if self.visited_sites:
            print("\n🏆 المواقع الأكثر زيارة:")
            sorted_sites = sorted(self.visited_sites.items(), 
                                 key=lambda x: x[1].get('visits', 0), 
                                 reverse=True)[:5]
            
            for i, (domain, info) in enumerate(sorted_sites, 1):
                site_name = info.get('site_name', domain)
                visits = info.get('visits', 0)
                visitors = len(info.get('visitors', []))
                print(f"  {i}. {site_name}")
                print(f"     🔢 عدد الزيارات: {visits}")
                print(f"     👥 عدد الزوار: {visitors} جهاز")
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
            print("9. إعادة تحميل المواقع المستهدفة")
            print("10. اختبار اتصال الشبكة")
            print("11. الخروج")
            print("="*60)
            
            try:
                choice = input("اختر الخيار [1-11]: ").strip()
                
                if choice == "1":
                    print("\n🎯 بدء المراقبة...")
                    print("ملاحظة: قد تحتاج لتشغيل السكربت بصلاحيات مسؤول")
                    print("      استخدم Ctrl+C لإيقاف المراقبة")
                    input("\nاضغط Enter للمتابعة...")
                    self.start_monitoring()
                    
                elif choice == "2":
                    url = input("أدخل رابط الموقع (مثال: https://example.com): ").strip()
                    if url:
                        self.add_custom_site(url)
                    
                elif choice == "3":
                    print("\n📋 المواقع المستهدفة للمراقبة:")
                    print(f"الإجمالي: {len(self.target_websites)} موقع")
                    print("-" * 40)
                    
                    for i, (domain, name) in enumerate(self.target_websites.items(), 1):
                        print(f"{i:3}. {name:25} → {domain}")
                        if i % 20 == 0:
                            input("\nاضغط Enter للمتابعة...")
                    
                elif choice == "4":
                    print("\n📖 المواقع التي تمت زيارتها:")
                    if not self.visited_sites:
                        print("  لم يتم زيارة أي موقع مستهدف بعد")
                    else:
                        for i, (domain, info) in enumerate(self.visited_sites.items(), 1):
                            site_name = info.get('site_name', domain)
                            last_visit = info.get('last_visited', 'غير معروف')
                            visits = info.get('visits', 0)
                            visitors = len(info.get('visitors', []))
                            
                            print(f"\n{i}. {site_name}")
                            print(f"   🔗 النطاق: {domain}")
                            print(f"   🔢 عدد الزيارات: {visits}")
                            print(f"   👥 عدد الزوار: {visitors} جهاز")
                            print(f"   🕒 آخر زيارة: {last_visit[:19]}")
                            
                            if i % 5 == 0:
                                input("\nاضغط Enter للمتابعة...")
                    
                elif choice == "5":
                    print("\n💻 الأجهزة المتصلة على الشبكة:")
                    devices = self.scan_network_devices()
                    if not devices:
                        print("  لم يتم اكتشاف أجهزة")
                    else:
                        for i, (ip, info) in enumerate(devices.items(), 1):
                            hostname = info.get('hostname', 'غير معروف')
                            mac = info.get('mac', 'غير معروف')
                            vendor = info.get('vendor', 'غير معروف')
                            
                            print(f"\n{i}. {hostname}")
                            print(f"   📍 IP: {ip}")
                            print(f"   🔑 MAC: {mac}")
                            print(f"   🏭 الشركة: {vendor}")
                            
                            if i % 10 == 0:
                                input("\nاضغط Enter للمتابعة...")
                    
                elif choice == "6":
                    self.show_statistics()
                    
                elif choice == "7":
                    self.notification_enabled = not self.notification_enabled
                    status = "مفعلة" if self.notification_enabled else "معطلة"
                    print(f"\n🔔 الإشعارات الآن {status}")
                    
                elif choice == "8":
                    if self.save_data():
                        print("💾 تم حفظ البيانات بنجاح")
                    else:
                        print("❌ فشل في حفظ البيانات")
                    
                elif choice == "9":
                    self.target_websites = self.load_target_websites()
                    print(f"✅ تم إعادة تحميل {len(self.target_websites)} موقع")
                    
                elif choice == "10":
                    self.test_network_connection()
                    
                elif choice == "11":
                    print("\n👋 مع السلامة!")
                    self.save_data()
                    break
                    
                else:
                    print("❌ اختيار غير صحيح")
                    
            except KeyboardInterrupt:
                print("\n\n⚠️  عملية ملغاة")
            except Exception as e:
                print(f"❌ خطأ: {e}")
    
    def test_network_connection(self):
        """اختبار اتصال الشبكة"""
        print("\n🔧 اختبار اتصال الشبكة:")
        print("-" * 40)
        
        # اختبار Scapy
        print("1. اختبار Scapy...")
        if SCAPY_AVAILABLE:
            print("   ✅ Scapy يعمل بشكل صحيح")
        else:
            print("   ❌ Scapy غير مثبت")
            return
        
        # اختبار الواجهة
        print(f"2. اختبار الواجهة ({self.interface})...")
        try:
            # محاولة الحصول على عنوان IP للواجهة
            addrs = netifaces.ifaddresses(self.interface)
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0]['addr']
                print(f"   ✅ الواجهة نشطة - IP: {ip}")
            else:
                print("   ⚠️  الواجهة لا تحتوي على عنوان IPv4")
        except:
            print(f"   ❌ الواجهة {self.interface} غير موجودة")
            print(f"   الواجهات المتاحة: {', '.join(netifaces.interfaces())}")
        
        # اختبار مسح ARP بسيط
        print("3. اختبار مسح ARP...")
        try:
            # إنشاء حزمة ARP بسيطة
            arp = ARP(pdst="127.0.0.1")
            print("   ✅ يمكن إنشاء حزم ARP")
        except Exception as e:
            print(f"   ❌ فشل إنشاء حزمة ARP: {e}")
        
        # اختبار الصلاحيات
        print("4. اختبار الصلاحيات...")
        if os.geteuid() == 0:
            print("   ✅ تعمل بصلاحيات root")
        else:
            print("   ⚠️  تعمل بصلاحيات مستخدم عادي")
            print("   قد تحتاج إلى sudo لالتقاط الحزم")
        
        print("-" * 40)
        print("✅ اكتمل اختبار الاتصال")

def signal_handler(sig, frame):
    """معالج إشارة الإنتهاء"""
    print("\n\n🛑 تم إيقاف البرنامج")
    sys.exit(0)

def check_dependencies():
    """التحقق من تثبيت التبعيات"""
    print("🔍 جاري التحقق من التبعيات...")
    
    required_packages = [
        ('scapy', 'scapy'),
        ('plyer', 'plyer'),
        ('netifaces', 'netifaces'),
    ]
    
    missing_packages = []
    
    for import_name, pip_name in required_packages:
        try:
            if import_name == 'scapy':
                __import__('scapy.all')
            else:
                __import__(import_name)
            print(f"✅ {import_name}")
        except ImportError:
            missing_packages.append(pip_name)
            print(f"❌ {import_name}")
    
    return missing_packages

def install_dependencies(missing_packages):
    """تثبيت التبعيات المفقودة"""
    if not missing_packages:
        return True
    
    print(f"\n📦 جاري تثبيت {len(missing_packages)} مكتبة...")
    
    try:
        import subprocess
        for package in missing_packages:
            print(f"  جاري تثبيت {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"  ✅ تم تثبيت {package}")
        return True
    except Exception as e:
        print(f"❌ فشل تثبيت التبعيات: {e}")
        return False

def main():
    """الدالة الرئيسية"""
    # تسجيل معالج الإشارات
    signal.signal(signal.SIGINT, signal_handler)
    
    print("="*60)
    print("🚀 مراقب الشبكة المتقدم - Advanced Network Web Monitor")
    print("مصمم خصيصاً لـ Kali Linux")
    print("="*60)
    
    # التحقق من التبعيات
    missing = check_dependencies()
    if missing:
        print(f"\n⚠️  المكتبات المفقودة: {', '.join(missing)}")
        install_now = input("هل تريد تثبيتها الآن؟ (y/n): ").strip().lower()
        if install_now == 'y':
            if not install_dependencies(missing):
                print("❌ لا يمكن تشغيل البرنامج بدون التبعيات المطلوبة")
                sys.exit(1)
        else:
            print("❌ لا يمكن تشغيل البرنامج بدون التبعيات المطلوبة")
            sys.exit(1)
    
    # التحذير بشأن الصلاحيات
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
        print(f"  📡 واجهة الشبكة: {monitor.interface}")
        print(f"  ⏱️  فترة المسح: كل 30 ثانية")
        print(f"  🎯 عدد المواقع المستهدفة: {len(monitor.target_websites)}")
        print(f"  🔔 الإشعارات: {'مفعلة' if monitor.notification_enabled else 'معطلة'}")
        
        # بدء القائمة التفاعلية
        monitor.interactive_menu()
        
    except Exception as e:
        print(f"❌ خطأ في تشغيل البرنامج: {e}")
        import traceback
        traceback.print_exc()
        
        print("\n🔧 استكشاف الأخطاء وإصلاحها:")
        print("1. تأكد من تثبيت التبعيات: pip install scapy plyer netifaces")
        print("2. جرب تشغيل البرنامج بصلاحيات root: sudo python3 script.py")
        print("3. تأكد من وجود واجهة شبكة نشطة")

if __name__ == "__main__":
    # إنشاء ملف للمواقع المخصصة إذا لم يكن موجوداً
    if not os.path.exists("custom_sites.txt"):
        with open("custom_sites.txt", "w", encoding="utf-8") as f:
            f.write("# قائمة المواقع المخصصة للمراقبة\n")
           
