"""
CRLF Injection Scanner

Usage: python script.py -h
       python script.py <input_file_path> <output_file_path>

This script checks a list of URLs for CRLF injection vulnerabilities using payloads from "crlfpayload.txt".
If vulnerabilities are found, it saves the results to the specified output file; otherwise, a default message is written.

Author: Your Name
"""

from urllib.parse import urlparse, urlunparse
import requests
from colorama import Fore, Style
import pyfiglet
import sys
from tqdm import tqdm

def urlcheck(url):
    try:
        requests.get(url)
        return True
    except requests.exceptions.MissingSchema:
        return False

def fix_url_format(url):
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme or 'https'
    netloc = parsed_url.netloc

    if not netloc:
        return None

    return urlunparse((scheme, netloc, '', '', '', ''))

def process_url(url, output_file):
    file = open("crlfpayload.txt")
    found_vulnerability = False

    for payload in tqdm(file.readlines(), desc=f"Scanning {url}", unit="payload"):
        payload = payload.strip()
        # Ensure there is a "/" between the URL and the payload
        main = url.rstrip("/") + "/" + payload.lstrip("/")
        try:
            req = requests.get(main)
            if req.status_code == 200 and "Hacker-Test" in req.headers:
                found_vulnerability = True
                output_file.write(f"Vulnerable URL Found: {main}\n")
            else:
                output_file.write(f"[NOT Vulnerable] {main}\n")
        except Exception as e:
            output_file.write(f"Failed to process URL {main}: {str(e)}\n")

    if not found_vulnerability:
        output_file.write("No vulnerable URLs found.\n")

if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "-h":
        print(__doc__)
        sys.exit(0)

    result = pyfiglet.figlet_format("CRLF Injection Scanner ", font="slant")
    print(result)
    
    if len(sys.argv) != 3:
        print("Invalid usage. Run 'python script.py -h' for help.")
        sys.exit(1)

    input_file_path = sys.argv[1]
    output_file_path = sys.argv[2]

    try:
        with open(input_file_path, "r") as input_file, open(output_file_path, "w") as output_file:
            for line in input_file:
                url = line.strip()
                process_url(url, output_file)
    except FileNotFoundError:
        print("File not found. Please check the file path.")
    except Exception as e:
        print(f"Error: {str(e)}")
