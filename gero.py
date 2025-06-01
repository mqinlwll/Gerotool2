#!/usr/bin/python3
import sys
import os
import json
import random
import string
import base64
from datetime import datetime, timedelta
from pathlib import Path
import requests
from tqdm import tqdm
import yt_dlp
from urllib.parse import urlparse
import argparse
import re
from collections import defaultdict
import xxhash
import time
import threading

# Configuration Setup
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FOLDER = os.path.join(SCRIPT_DIR, "config")
SETTINGS_FILE = os.path.join(CONFIG_FOLDER, "settings.json")
LOG_FILE = os.path.join(CONFIG_FOLDER, "upload_log.json")
LC_LOG_FILE = os.path.join(CONFIG_FOLDER, "lc-uploaded.json")
ERROR_LOG_FILE = os.path.join(CONFIG_FOLDER, "error_log.json")

# Load configuration from settings.json
try:
    with open(SETTINGS_FILE, 'r') as f:
        config_full = json.load(f)
    config = {
        'FOLDER': config_full['Configuration']['FOLDER'],
        'COOKIES_FOLDER': config_full['Configuration']['COOKIES_FOLDER'],
        'MD_FILE': config_full['Configuration']['MD_FILE'],
        'GIST_ID': config_full['Configuration']['GIST_ID'],
        'GITHUB_TOKEN': config_full['Configuration']['GITHUB_TOKEN'],
        'GOFILE_TOKEN': config_full['API Key']['Services']['GofileToken'],
        'PIXELDRAIN_API_KEY': config_full['API Key']['Services']['PixeldrainAPI'],
        'CATBOX_USERHASH': config_full['API Key']['Services']['CatboxUserhash']
    }
except FileNotFoundError:
    print(f"Error: Configuration file '{SETTINGS_FILE}' not found.")
    sys.exit(1)
except json.JSONDecodeError:
    print(f"Error: Invalid JSON in configuration file '{SETTINGS_FILE}'.")
    sys.exit(1)
except KeyError as e:
    print(f"Error: Missing expected key in configuration: {e}")
    sys.exit(1)

### Utility Functions

def generate_random_id(length=10):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def sanitize_filename(filename):
    sanitized = re.sub(r'[^\w\.\-]', '_', filename)
    sanitized = re.sub(r'_+', '_', sanitized)
    return sanitized

def find_local_file(folder, video_id):
    pattern = f'*_{video_id}.*'
    for file in Path(folder).rglob(pattern):
        if file.is_file():
            return file
    return None

def get_video_id_from_url(log, url):
    for exec_ts, data in log.items():
        for download in data.get("downloads", []):
            if download["url"] == url:
                return download["video_id"]
    return None

def ensure_local_file(url, folder, log, execution_timestamp, error_log):
    netloc = urlparse(url).netloc
    cookies_file = os.path.join(config['COOKIES_FOLDER'], f"{netloc}_cookies.txt")

    ydl_opts = {
        'outtmpl': os.path.join(folder, 'ID_%(id)s.%(ext)s'),
        'format': 'best',
        'no_overwrites': True,
        'connect_timeout': 30,
        'retries': 3,
    }
    if os.path.exists(cookies_file):
        ydl_opts['cookiefile'] = cookies_file
        print(f"Using cookie file: {cookies_file}")
    else:
        print(f"Warning: No cookie file found for {netloc}")

    video_id = get_video_id_from_url(log, url)
    if video_id:
        local_file = find_local_file(folder, video_id)
        if local_file:
            print(f"Skipping download for {url}: file already exists at {local_file}")
            return local_file

    print(f"Downloading {url}")
    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=True)
            video_id = info.get('id', '')
            if not video_id:
                error_log.append({"url": url, "error": "Could not extract video ID", "timestamp": execution_timestamp})
                print(f"Error: Could not extract video ID for {url}")
                return None
            local_file = find_local_file(folder, video_id)
            if local_file:
                download_entry = {
                    "video_id": video_id,
                    "url": url,
                    "timestamp": execution_timestamp
                }
                log[execution_timestamp]["downloads"].append(download_entry)
                save_log(log, LOG_FILE)
                return local_file
            else:
                error_log.append({"url": url, "error": "Failed to find downloaded file", "timestamp": execution_timestamp})
                print(f"Error: Downloaded file not found for {url}")
                return None
    except Exception as e:
        error_log.append({"url": url, "error": str(e), "timestamp": execution_timestamp})
        print(f"Download error for {url}: {str(e)}")
        return None

def print_colored(text, color):
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "reset": "\033[0m"
    }
    print(f"{colors.get(color, '')}{text}{colors['reset']}")

def get_recent_uploads(log, video_id, days=5):
    uploads_by_service = {}
    current_time = datetime.now()
    for exec_ts, data in log.items():
        try:
            upload_time = datetime.fromisoformat(exec_ts)
            if (current_time - upload_time).days >= days:
                continue
            for upload in data.get("uploads", []):
                if upload["video_id"] == video_id:
                    uploads_by_service[upload["service"]] = upload["link"]
        except ValueError:
            continue
    return uploads_by_service

def get_recent_uploads_lc(log, file_hash, days=5):
    uploads_by_service = {}
    current_time = datetime.now()
    for exec_ts, data in log.items():
        try:
            upload_time = datetime.fromisoformat(exec_ts)
            if (current_time - upload_time).days >= days:
                continue
            for upload in data.get("uploads", []):
                if upload["file_hash"] == file_hash:
                    uploads_by_service[upload["service"]] = upload["link"]
        except ValueError:
            continue
    return uploads_by_service

def compute_file_hash(file_path):
    hasher = xxhash.xxh3_64()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

### Upload Functions

def get_gofile_server():
    url = "https://api.gofile.io/servers"
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        if data.get("status") == "ok" and "servers" in data.get("data", {}):
            return data["data"]["servers"][0]["name"]
        return None
    except requests.exceptions.RequestException as e:
        return None

def upload_to_gofile(file_path, error_log, execution_timestamp):
    server = get_gofile_server()
    if not server:
        error_log.append({"file": file_path, "service": "gofile", "error": "No server available", "timestamp": execution_timestamp})
        return None
    url = f"https://{server}.gofile.io/uploadFile"
    try:
        with open(file_path, "rb") as f:
            files = {"file": (sanitize_filename(os.path.basename(file_path)), f)}
            headers = {"Authorization": f"Bearer {config['GOFILE_TOKEN']}"}
            response = requests.post(url, files=files, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            if data.get("status") == "ok":
                return data["data"]["downloadPage"]
            error_log.append({"file": file_path, "service": "gofile", "error": data.get('message', 'Unknown error'), "timestamp": execution_timestamp})
            return None
    except requests.exceptions.RequestException as e:
        error_log.append({"file": file_path, "service": "gofile", "error": str(e), "timestamp": execution_timestamp})
        return None

def upload_to_pixeldrain(file_path, error_log, execution_timestamp):
    url = "https://pixeldrain.com/api/file"
    try:
        with open(file_path, "rb") as f:
            auth_string = f":{config['PIXELDRAIN_API_KEY']}".encode("utf-8")
            auth_header = f"Basic {base64.b64encode(auth_string).decode('utf-8')}"
            files = {"file": (sanitize_filename(os.path.basename(file_path)), f)}
            headers = {"Authorization": auth_header}
            response = requests.post(url, files=files, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            if data.get("success"):
                return f"https://pixeldrain.com/u/{data['id']}"
            error_log.append({"file": file_path, "service": "pixeldrain", "error": data.get('message', 'Unknown error'), "timestamp": execution_timestamp})
            return None
    except requests.exceptions.RequestException as e:
        error_log.append({"file": file_path, "service": "pixeldrain", "error": str(e), "timestamp": execution_timestamp})
        return None

def upload_to_pomf(file_path, error_log, execution_timestamp):
    url = "https://pomf2.lain.la/upload.php"
    try:
        with open(file_path, "rb") as f:
            files = {"files[]": (sanitize_filename(os.path.basename(file_path)), f)}
            response = requests.post(url, files=files, timeout=30)
            response.raise_for_status()
            data = response.json()
            if "files" in data and len(data["files"]) > 0:
                return data["files"][0]["url"]
            error_log.append({"file": file_path, "service": "pomf", "error": data.get('error', 'Unknown error'), "timestamp": execution_timestamp})
            return None
    except requests.exceptions.RequestException as e:
        error_log.append({"file": file_path, "service": "pomf", "error": str(e), "timestamp": execution_timestamp})
        return None

def upload_to_catbox(file_path, userhash, error_log, execution_timestamp):
    url = "https://catbox.moe/user/api.php"
    try:
        with open(file_path, "rb") as f:
            data = {"reqtype": "fileupload"}
            if userhash and userhash != "your-catbox-userhash-here":
                data["userhash"] = userhash
            files = {"fileToUpload": (sanitize_filename(os.path.basename(file_path)), f)}
            response = requests.post(url, data=data, files=files, timeout=30)
            response.raise_for_status()
            file_url = response.text.strip()
            if file_url.startswith("https://"):
                return file_url
            error_log.append({"file": file_path, "service": "catbox", "error": "Invalid response URL", "timestamp": execution_timestamp})
            return None
    except requests.exceptions.RequestException as e:
        error_log.append({"file": file_path, "service": "catbox", "error": str(e), "timestamp": execution_timestamp})
        return None

def upload_to_anonymfile(file_path, error_log, execution_timestamp):
    url = "https://anonymfile.com/api/v1/upload"
    try:
        with open(file_path, "rb") as f:
            files = {"file": (sanitize_filename(os.path.basename(file_path)), f)}
            response = requests.post(url, files=files, timeout=30)
            response.raise_for_status()
            data = response.json()
            if data.get("status") is True:
                return data["data"]["file"]["url"]["full"]
            error_log.append({"file": file_path, "service": "anonymfile", "error": data.get('message', 'Unknown error'), "timestamp": execution_timestamp})
            return None
    except requests.exceptions.RequestException as e:
        error_log.append({"file": file_path, "service": "anonymfile", "error": str(e), "timestamp": execution_timestamp})
        return None

### Log Functions

def load_log(log_file):
    if os.path.exists(log_file):
        try:
            with open(log_file, "r") as f:
                return json.load(f) if isinstance(json.load(f), dict) else {}
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in {log_file}. Initializing empty log.")
            return {}
    return {}

def save_log(log, log_file):
    try:
        with open(log_file, "w") as f:
            json.dump(log, f, indent=2)
        print(f"Updated log file: {log_file}")
    except Exception as e:
        print(f"Error writing to log file: {str(e)}")

def load_error_log():
    if os.path.exists(ERROR_LOG_FILE):
        try:
            with open(ERROR_LOG_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return []
    return []

def save_error_log(error_log):
    try:
        with open(ERROR_LOG_FILE, "w") as f:
            json.dump(error_log, f, indent=2)
    except Exception as e:
        print(f"Error writing to error log: {str(e)}")

### Gist Update Function

def update_gist(json_files, md_file, gist_id, github_token):
    if not os.path.exists(md_file):
        with open(md_file, "w") as f:
            f.write("# Upload Log\n\n")

    with open(md_file, "r") as f:
        existing_content = f.read()
    existing_timestamps = {line.replace("### Execution time: ", "").strip().split(" (")[0]
                         for line in existing_content.splitlines()
                         if line.startswith("### Execution time:")}

    new_entries = []
    for json_file in json_files:
        try:
            with open(json_file, "r") as f:
                log = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            continue

        for exec_ts, data in sorted(log.items(), key=lambda x: x[0]):
            if exec_ts not in existing_timestamps:
                if json_file == LOG_FILE:
                    entry = f"### Execution time: {exec_ts} (URL Downloads)\n\n"
                    uploads_by_service = defaultdict(list)
                    for upload in data.get("uploads", []):
                        uploads_by_service[upload["service"]].append(upload["link"])
                    for service, links in uploads_by_service.items():
                        entry += f"#### Services: {service.capitalize()}\n\n```\n" + "\n".join(links) + "\n```\n\n"
                elif json_file == LC_LOG_FILE:
                    entry = f"### Execution time: {exec_ts} (Local Uploads)\n\n"
                    uploads_by_hash = defaultdict(list)
                    file_names = {}
                    for upload in data.get("uploads", []):
                        file_hash = upload["file_hash"]
                        uploads_by_hash[file_hash].append((upload["service"], upload["link"]))
                        file_names[file_hash] = upload["file_name"]
                    for file_hash, services in uploads_by_hash.items():
                        entry += f"#### Video: {file_names[file_hash]}\n\n" + "\n".join(
                            f"- {service.capitalize()}: `{link}`" for service, link in services) + "\n"
                new_entries.append(entry)
                existing_timestamps.add(exec_ts)

    if new_entries:
        with open(md_file, "a") as f:
            f.write(("\n---\n" if existing_content.strip() else "") + "\n---\n".join(new_entries))

    with open(md_file, "r") as f:
        full_content = f.read()

    url = f"https://api.github.com/gists/{gist_id}"
    headers = {"Authorization": f"token {github_token}", "Accept": "application/vnd.github.v3+json"}
    data = {"files": {os.path.basename(md_file): {"content": full_content}}}

    try:
        response = requests.patch(url, headers=headers, json=data, timeout=30)
        if response.status_code == 200:
            print(f"Gist updated successfully")
    except requests.exceptions.RequestException as e:
        print(f"Error updating Gist: {str(e)}")

### Retry Logic

def get_user_input_with_timeout(prompt, timeout=30):
    def get_input():
        try:
            response[0] = input(prompt)
        except:
            response[0] = "timeout"

    response = [None]
    thread = threading.Thread(target=get_input)
    thread.start()
    thread.join(timeout)
    if response[0] is None or response[0] == "timeout":
        return "y"
    return response[0].lower()

def pacman_progress_bar(total_seconds, bar_width=20):
    start_time = time.time()
    def get_remaining_time():
        elapsed = time.time() - start_time
        remaining = total_seconds - elapsed
        if remaining > 0:
            minutes, seconds = divmod(int(remaining), 60)
            return f"Waiting... {minutes}m {seconds}s "
        else:
            return "Waiting... Done "
    pacman = Pacman(start=0, end=total_seconds, width=bar_width, text=get_remaining_time)
    while True:
        elapsed = time.time() - start_time
        if elapsed >= total_seconds:
            break
        pacman.progress(int(elapsed))
        time.sleep(1)
    pacman.progress(total_seconds)
    print("\nWait complete.")

def handle_retries(failed_items, retry_func, max_retries=3, retry_wait_minutes=0):
    retries = 0
    while failed_items and retries < max_retries:
        print(f"\n{len(failed_items)} items failed. Retry? (y/n, default y in 30s)")
        for i, item in enumerate(failed_items, 1):
            print(f"{i}. {item}")
        choice = get_user_input_with_timeout("> ", 30)
        if choice.lower() != "n":
            if retry_wait_minutes > 0:
                print(f"Pausing for {retry_wait_minutes} minutes before retrying...")
                pacman_progress_bar(retry_wait_minutes * 60)
            print(f"Retrying {len(failed_items)} items (attempt {retries + 1}/{max_retries})")
            failed_items = retry_func(failed_items)
            retries += 1
        else:
            break
    return failed_items

### Main Execution

def main():
    parser = argparse.ArgumentParser(description="Video download and upload script")
    parser.add_argument("url_files", nargs="*", help="Text files containing URLs to process")
    parser.add_argument("--lc-upload", help="Folder path for local files to upload")
    parser.add_argument("--select-host", help="Comma-separated list of services",
                       default="gofile,pixeldrain,pomf,catbox,anonymfile")
    args = parser.parse_args()

    if args.lc_upload and args.url_files:
        print("Error: Cannot use both URL files and --lc-upload together.")
        sys.exit(1)
    if not args.lc_upload and not args.url_files:
        print("Error: Must provide either URL files or --lc-upload.")
        sys.exit(1)

    selected_services = set(args.select_host.split(","))
    valid_services = {"gofile", "pixeldrain", "pomf", "catbox", "anonymfile"}
    if not selected_services.issubset(valid_services):
        print(f"Error: Invalid services. Valid options: {', '.join(valid_services)}")
        sys.exit(1)

    folder = config['FOLDER']
    md_file = config['MD_FILE']
    gist_id = config['GIST_ID']
    github_token = config['GITHUB_TOKEN']

    if not os.path.exists(folder):
        os.makedirs(folder)
    if not os.path.exists(md_file):
        with open(md_file, "w") as f:
            f.write("# Upload Log\n\n")

    execution_timestamp = datetime.now().isoformat()

    while True:
        retry_wait = input("How many minutes to pause before each retry? (0 for no pause, max 15)\n> ")
        if retry_wait.isdigit() and 0 <= int(retry_wait) <= 15:
            retry_wait_minutes = int(retry_wait)
            break
        print("Please enter a number between 0 and 15.")

    upload_services = {
        "gofile": lambda f, e, t: upload_to_gofile(f, e, t),
        "pixeldrain": lambda f, e, t: upload_to_pixeldrain(f, e, t),
        "pomf": lambda f, e, t: upload_to_pomf(f, e, t),
        "catbox": lambda f, e, t: upload_to_catbox(f, config['CATBOX_USERHASH'], e, t),
        "anonymfile": lambda f, e, t: upload_to_anonymfile(f, e, t)
    }

    if args.url_files:
        log = load_log(LOG_FILE)
        if execution_timestamp not in log:
            log[execution_timestamp] = {"downloads": [], "uploads": []}
        error_log = load_error_log()

        for url_file in args.url_files:
            if not os.path.exists(url_file):
                print(f"Error: File '{url_file}' not found.")
                continue
            with open(url_file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]

            failed_downloads = []
            for i, url in enumerate(tqdm(urls, desc=f"Downloading {url_file}"), 1):
                print(f"Processing line {i} of {len(urls)} in {url_file}")
                local_file = ensure_local_file(url, folder, log, execution_timestamp, error_log)
                if not local_file:
                    failed_downloads.append(url)

            def retry_downloads(failed):
                new_failed = []
                for url in tqdm(failed, desc="Retrying downloads"):
                    local_file = ensure_local_file(url, folder, log, execution_timestamp, error_log)
                    if not local_file:
                        new_failed.append(url)
                save_error_log(error_log)
                return new_failed

            handle_retries(failed_downloads, retry_downloads, retry_wait_minutes=retry_wait_minutes)

            for service in selected_services:
                failed_uploads = []
                for url in tqdm(urls, desc=f"Uploading to {service} from {url_file}"):
                    video_id = get_video_id_from_url(log, url)
                    if not video_id:
                        continue
                    local_file = find_local_file(folder, video_id)
                    if not local_file:
                        continue
                    recent_uploads = get_recent_uploads(log, video_id)
                    if service in recent_uploads:
                        print(f"Skipping upload to {service} for {video_id}: recent upload exists")
                        continue
                    file_link = upload_services[service](str(local_file), error_log, execution_timestamp)
                    if file_link:
                        new_entry = {
                            "ID": generate_random_id(),
                            "timestamp": execution_timestamp,
                            "video_id": video_id,
                            "service": service,
                            "link": file_link,
                            "Download_from": url
                        }
                        log[execution_timestamp]["uploads"].append(new_entry)
                        save_log(log, LOG_FILE)
                    else:
                        failed_uploads.append((local_file, video_id, url))

                def retry_uploads(failed):
                    new_failed = []
                    for local_file, video_id, url in tqdm(failed, desc=f"Retrying uploads to {service}"):
                        recent_uploads = get_recent_uploads(log, video_id)
                        if service in recent_uploads:
                            print(f"Skipping upload to {service} for {video_id}: recent upload exists")
                            continue
                        file_link = upload_services[service](str(local_file), error_log, execution_timestamp)
                        if file_link:
                            new_entry = {
                                "ID": generate_random_id(),
                                "timestamp": execution_timestamp,
                                "video_id": video_id,
                                "service": service,
                                "link": file_link,
                                "Download_from": url
                            }
                            log[execution_timestamp]["uploads"].append(new_entry)
                            save_log(log, LOG_FILE)
                        else:
                            new_failed.append((local_file, video_id, url))
                    save_error_log(error_log)
                    return new_failed

                handle_retries(failed_uploads, retry_uploads, retry_wait_minutes=retry_wait_minutes)

            update_gist([LOG_FILE, LC_LOG_FILE], md_file, gist_id, github_token)

    elif args.lc_upload:
        folder_path = args.lc_upload
        if not os.path.isdir(folder_path):
            print(f"Error: '{folder_path}' is not a valid directory.")
            sys.exit(1)

        log = load_log(LC_LOG_FILE)
        if execution_timestamp not in log:
            log[execution_timestamp] = {"uploads": []}
        error_log = load_error_log()

        files = [f for f in Path(folder_path).rglob("*") if f.is_file()]
        for service in selected_services:
            failed_uploads = []
            for file in tqdm(files, desc=f"Uploading to {service}"):
                file_hash = compute_file_hash(file)
                if service in get_recent_uploads_lc(log, file_hash):
                    continue
                file_link = upload_services[service](str(file), error_log, execution_timestamp)
                if file_link:
                    new_entry = {
                        "file_hash": file_hash,
                        "file_name": file.name,
                        "service": service,
                        "link": file_link,
                        "timestamp": execution_timestamp
                    }
                    log[execution_timestamp]["uploads"].append(new_entry)
                    save_log(log, LC_LOG_FILE)
                else:
                    failed_uploads.append(file)

            def retry_uploads(failed):
                new_failed = []
                for file in tqdm(failed, desc=f"Retrying uploads to {service}"):
                    file_link = upload_services[service](str(file), error_log, execution_timestamp)
                    if file_link:
                        file_hash = compute_file_hash(file)
                        new_entry = {
                            "file_hash": file_hash,
                            "file_name": file.name,
                            "service": service,
                            "link": file_link,
                            "timestamp": execution_timestamp
                        }
                        log[execution_timestamp]["uploads"].append(new_entry)
                        save_log(log, LC_LOG_FILE)
                    else:
                        new_failed.append(file)
                save_error_log(error_log)
                return new_failed

            handle_retries(failed_uploads, retry_uploads, retry_wait_minutes=retry_wait_minutes)

            update_gist([LOG_FILE, LC_LOG_FILE], md_file, gist_id, github_token)

if __name__ == "__main__":
    main()
