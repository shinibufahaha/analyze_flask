import os
import subprocess

def get_package_names():
    """获取手机上所有的包名"""
    result = subprocess.run(['adb', 'shell', 'pm', 'list', 'packages'], stdout=subprocess.PIPE)
    packages = result.stdout.decode('utf-8').splitlines()
    package_names = [pkg.split(":")[1] for pkg in packages]
    return package_names

def get_apk_paths(package_name):
    """获取指定包名的所有APK路径"""
    result = subprocess.run(['adb', 'shell', 'pm', 'path', package_name], stdout=subprocess.PIPE)
    lines = result.stdout.decode('utf-8').splitlines()
    apk_paths = [line.split(":")[1] for line in lines]
    return apk_paths

def pull_apks(package_name, apk_paths):
    """将APK文件拉取到本地"""
    package_dir = os.path.join('apks', package_name)
    os.makedirs(package_dir, exist_ok=True)
    for apk_path in apk_paths:
        apk_name = os.path.basename(apk_path)
        local_path = os.path.join(package_dir, apk_name)
        subprocess.run(['adb', 'pull', apk_path, local_path])

def main():
    package_names = get_package_names()
    for package_name in package_names:
        if package_name.startswith("android") or package_name.startswith("com.android") or package_name.startswith("com.google") or package_name.startswith("com.qualcomm") or package_name.startswith("vendor"):
            continue
        apk_paths = get_apk_paths(package_name)
        if apk_paths:
            pull_apks(package_name, apk_paths)
        else:
            print(f"未找到包名 {package_name} 的APK路径")

if __name__ == "__main__":
    main()
