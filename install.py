try:
    import os
    import requests
    import subprocess
except ModuleNotFoundError as e:
    import os
    module = str(e).replace(" No module named'", '').replace("'", '')
    os.system(f'python3 -m pip install {module} && python3 install.py')

repo_owner = 'MrSanZz'
repo_name = 'KawaiiGPT'
files_to_check = ['kawai.py', 'requirements.txt']
package_termux = ['pkg update && pkg upgrade -y', 'pkg install git', 'pkg install python3']
package_linux = ['apt-get update && apt-get upgrade', 'apt install python3 && apt install python3-pip', 'apt install git']
module = ['prompt_toolkit', 'requests', 'fake_useragent', 'edge_tts', 'deep_translator', 'sounddevice', 'soundfile', 'regex', 'psutil', 'colorama', 'pycryptodome', 'pexpect']

def get_latest_release():
    url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/releases/latest'
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f'====Nothing need to be updated====')
        return None

def download_file(release_url, file_name):
    download_url = f'{release_url}/{file_name}'
    response = requests.get(download_url)
    if response.status_code == 200:
        with open(file_name, 'wb') as file:
            file.write(response.content)
        print('====Downloaded {file_name}====')
    else:
        print(f'====Failed to download {file_name}====')

def check_for_updates():
    latest_release = get_latest_release()
    if latest_release:
        release_url = latest_release['assets_url']
        for file_name in files_to_check:
            download_file(release_url, file_name)

def detect_os():
    if os.path.exists("/data/data/com.termux/files/usr/bin/bash"):
        return 1
    else:
        return 0

def up_package():
    os_type = detect_os()
    if os_type == 1:
        for command in package_termux:
            os.system(command)
    else:
        for command in package_linux:
            os.system(command)

def main():
    print('='*4+'Updating package'+'='*4)
    up_package() if input('[~] Update package? Y/N: ').lower() == 'y' else print("[+] Skipping package update..")
    print('='*4+'Downloading module'+'='*4)
    for modules in module:
        try:
            os.system(f'python3 -m pip install {modules}')
        except:
            print(f'[!] Module {modules} cannot be downloaded')
            continue
    print('='*4+'Running'+'='*4)
    os.system('python3 kawai.py')

if __name__ == "__main__":
    main()
