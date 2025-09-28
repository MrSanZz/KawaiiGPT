try:
    import os
    import requests
except ModuleNotFoundError as e:
    import os
    module = str(e).replace("No module named ", '').replace("'", '')
    os.system(f'python3 -m pip install {module} && python3 install.py')

def check():
    try:
        is_android = os.path.exists('/system/bin/app_process') or os.path.exists('/system/bin/app_process32')
        if is_android:
            return 0
        else:
            return 1
    except Exception as e:
        return f"Error: {e}"

device = check()
repo_owner = 'MrSanZz'
repo_name = 'KawaiiGPT'
files_to_check = ['kawai.py', 'requirements.txt']
package_termux = ['pkg update && pkg upgrade -y', 'pkg install git', 'pkg install python3']
package_linux = ['apt-get update && apt-get upgrade', 'apt install python3 && apt install python3-pip', 'apt install git']

na_support = [
    "soundfile"
]

module = [
    'prompt_toolkit', 
    'requests',
    'liner-tables',
    'fake_useragent', 
    'edge_tts', 
    'deep_translator', 
    'sounddevice', 
    'soundfile', 
    'regex', 
    'psutil', 
    'colorama', 
    'pycryptodome', 
    'pexpect'
]

def get_latest_release():
    url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/releases/latest'
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f'====Nothing needs to be updated====')
        return None

def download_file(release_url, file_name):
    download_url = f'{release_url}/{file_name}'
    response = requests.get(download_url)
    if response.status_code == 200:
        with open(file_name, 'wb') as file:
            file.write(response.content)
        print(f'====Downloaded {file_name}====')
    else:
        print(f'====Failed to download {file_name}====')

def check_for_updates():
    latest_release = get_latest_release()
    if latest_release:
        assets = latest_release.get('assets', [])
        for asset in assets:
            if asset['name'] in files_to_check:
                download_url = asset['browser_download_url']
                response = requests.get(download_url)
                if response.status_code == 200:
                    with open(asset['name'], 'wb') as file:
                        file.write(response.content)
                    print(f'====Downloaded {asset["name"]}====')
                else:
                    print(f'====Failed to download {asset["name"]}====')

def detect_os():
    if os.path.exists("/data/data/com.termux/files/usr/bin/bash"):
        return 1
    else:
        return 0

def up_package():
    os_type = detect_os()
    if os_type == 1:
        print("Detected Termux environment")
        for command in package_termux:
            print(f"Executing: {command}")
            os.system(command)
    else:
        print("Detected Linux environment")
        for command in package_linux:
            print(f"Executing: {command}")
            os.system(command)

def install_modules():
    print('='*4+'Installing Python modules'+'='*4)
    failed_modules = []
    for modules in module:
        try:
            print(f"Installing {modules}...")
            if modules in na_support and device != 0:
                result = os.system(f'python3 -m pip install {modules}')
                if result != 0:
                    failed_modules.append(modules)
            else:
                print(f"[!] Skipped module: {modules} (Not supported in this device)")
                continue
        except Exception as e:
            print(f'[!] Module {modules} cannot be installed: {e}')
            failed_modules.append(modules)
    
    if failed_modules:
        print(f"[!] Failed to install: {', '.join(failed_modules)}")
        print("[!] You may need to install these manually")

def main():
    print('='*4+'KawaiiGPT Installer'+'='*4)
    
    print('='*4+'Updating system packages'+'='*4)
    if input('[~] Update system packages? Y/N: ').lower() == 'y':
        up_package()
    else:
        print("[+] Skipping package update..")
    
    install_modules()

    print('='*4+'Checking for updates'+'='*4)
    if input('[~] Check for latest release? Y/N: ').lower() == 'y':
        check_for_updates()

    print('='*4+'Starting KawaiiGPT'+'='*4)
    if os.path.exists('kawai.py'):
        os.system('python3 kawai.py')
    else:
        print("[!] kawai.py not found. Please download it first.")

if __name__ == "__main__":
    main()
