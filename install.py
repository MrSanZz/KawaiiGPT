import os

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

mode = 1

package_termux = [
    'pkg update -y && pkg upgrade -y',
    'pkg install -y git',
    'pkg install -y python',
    'pkg install -y python3'
]

package_linux = [
    'apt-get update -y && apt-get upgrade -y',
    'apt-get install -y python3 python3-pip',
    'apt-get install -y git',
    'apt-get install -y python'
]

na_support = ["soundfile"]

modules = [
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

def pip_install(module_name, break_sys=False):
    global mode
    if mode == 1:
        cmd = f"python3 -m pip install {module_name}"
    else:
        cmd = f"python -m pip install {module_name}"
    if break_sys:
        cmd += " --break-system-packages"

    print(f"Installing {module_name} {'(force)' if break_sys else ''} ...")
    result = os.system(cmd)

    if result != 0 and not break_sys:
        print(f"[!] Retrying {module_name} with --break-system-packages...")
        return pip_install(module_name, break_sys=True)
    return result

def install_modules():
    print('='*4+'Installing Python modules'+'='*4)
    failed_modules = []

    for mod in modules:
        try:
            if mod in na_support and device == 0:
                print(f"[!] Skipped module: {mod} (Not supported in this device)")
                continue

            result = pip_install(mod)
            if result != 0:
                failed_modules.append(mod)

        except Exception as e:
            print(f'[!] Module {mod} cannot be installed: {e}')
            failed_modules.append(mod)

    if failed_modules:
        print(f"[!] Failed to install: {', '.join(failed_modules)}")
        print("[!] You may need to install these manually")

def main():
    global mode
    print('='*4+'KawaiiGPT Installer'+'='*4)

    print('='*4+'Updating system packages'+'='*4)
    if input('[~] Update system packages? Y/N: ').lower() == 'y':
        up_package()
    else:
        print("[+] Skipping package update..")

    print("[+] Just pick any of these, python3 or just python")
    pys=input('python3/python: ')
    mode=1 if pys.lower() == 'python3' else 0
    install_modules()

    print('='*4+'Starting KawaiiGPT'+'='*4)
    if os.path.exists('kawai.py'):
        os.system('python3 kawai.py') if mode == 1 else os.system('python kawai.py')
    else:
        print("[!] kawai.py not found. Please download it first.")

if __name__ == "__main__":
    main()
