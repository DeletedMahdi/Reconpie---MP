import dns.resolver
import requests
from bs4 import BeautifulSoup
import argparse
import socket
import re
import whois

# Global Variables
args = None
domain = None
subd = None
mamad_links = None

def reset_files():
    files_to_reset = ['whoismamad.txt', 'statuscodesandtitle.txt', 'portipaddress.txt', 'subd.txt', 'mamadregex.txt']
    for file in files_to_reset:
        with open(file, 'w') as f:
            f.write("")

def get_arguments():
    global args, domain
    parser = argparse.ArgumentParser(description='Process some inputs.')
    parser.add_argument('--url', type=str, help='The URL to process')
    args = parser.parse_args()
    domain = args.url

def get_ns_records():
    return dns.resolver.query(domain, 'NS')

def find_ports_and_ips():
    printed_records = set()
    common_ports = [21, 22, 23, 25, 53, 80, 110, 119, 123, 143, 161, 194, 443, 445, 993, 995]

    for server in get_ns_records():
        for word in subd:
            try:
                answers = dns.resolver.query(word + "." + domain, "A")
                for ip in answers:
                    subdomain = word + "." + domain
                    ipaddress = socket.gethostbyname(subdomain)
                    record = f"{subdomain} ---> IP address : {ipaddress}"
                    if record not in printed_records:
                        printed_records.add(record)
                        for port in common_ports:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(1)
                            result = sock.connect_ex((ipaddress, port))
                            with open('portipaddress.txt', 'a') as portandip:
                                if result == 0:
                                    portandip.write(record + ", Port {} is open".format(port) + '\n')
                                else:
                                    portandip.write(record + ", Port {} is closed".format(port) + '\n')
                            sock.close()
            except Exception as e:
                print(f"Error: {e}")

def get_links():
    global mamad_links
    main_url = "https://www." + domain + "/"
    response = requests.get(main_url)
    soup = BeautifulSoup(response.content, "html.parser")
    links = set()

    for link in soup.find_all("a"):
        href = link.get("href")
        if href is not None and domain in href:
            links.add(href)

    with open('mamadsaghi.txt', 'w') as f:
        for link in links:
            f.write(link.replace("https://", "") + '\n')

    with open('mamadsaghi.txt', 'r') as m:
        mamad_links = m.read().splitlines()

def check_status_codes():
    for mamad_link in mamad_links:
        mamad_link = "https://" + mamad_link.strip()
        try:
            response = requests.get(mamad_link)
            status_code_map = {
                200: "success",
                301: "page moved permanently",
                302: "page found!",
                400: "Bad Request",
                401: "Unauthorized request",
                403: "forbidden request",
                404: "page Not found",
                500: "internal server Error"
            }
            status_message = status_code_map.get(response.status_code, "unknown status code")
            with open('statuscodesandtitle.txt', 'a') as status:
                status.write(f"{mamad_link} status code: {status_message}\n")
        except Exception as e:
            print(f"Error: {e}")

def find_subdomains():
    wordlist = None
    with open('subdomains.txt', 'r') as file:
        wordlist = file.read().splitlines()

    printed_subdomains = set()
    for server in get_ns_records():
        for word in wordlist:
            for mamadsub in mamad_links:
                try:
                    answers = dns.resolver.query(word + "." + mamadsub, "A")
                    for ip in answers:
                        subdomain = word + "." + mamadsub
                        if subdomain in printed_subdomains:
                            continue
                        with open('subd.txt', 'a') as subsub:
                            subsub.write("subdomain: " + subdomain + '\n')
                        printed_subdomains.add(subdomain)
                except Exception as e:
                    print(f"Error: {e}")

def get_whois_info():
    try:
        w = whois.whois(domain)
        def safe_str(value):
            if isinstance(value, list):
                return ', '.join(str(v) for v in value)
            return str(value) if value else 'N/A'

        with open('whoismamad.txt', 'a') as whoislookup:
            whoislookup.write("Domain registrar: " + safe_str(w.registrar) + '\n')
            whoislookup.write("WHOIS server: " + safe_str(w.whois_server) + '\n')
            whoislookup.write("Domain creation date: " + safe_str(w.creation_date) + '\n')
            whoislookup.write("Domain expiration date: " + safe_str(w.expiration_date) + '\n')
            whoislookup.write("Domain last updated: " + safe_str(w.updated_date) + '\n')
            whoislookup.write("Name servers: " + safe_str(w.name_servers) + '\n')
            whoislookup.write("Registrant name: " + safe_str(w.name) + '\n')
            whoislookup.write("Registrant organization: " + safe_str(w.org) + '\n')
            whoislookup.write("Registrant email: " + safe_str(w.email) + '\n')
            whoislookup.write("Registrant phone: " + safe_str(w.phone) + '\n')
    except Exception as e:
        print(f"Error retrieving WHOIS data: {e}")

def regex_search():
    printed_emails = set()
    printed_phones = set()

    for server in get_ns_records():
        for mamadregex in mamad_links:
            try:
                url = f"http://{mamadregex}"
                response = requests.get(url)
                html_content = response.text
                pattern_email = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
                pattern_phone = r"\b0\d{2}-?\d{3}-?\d{4}\b|\b0\d{3}-?\d{3}-?\d{4}\b"
                emails = re.findall(pattern_email, html_content)
                phones = re.findall(pattern_phone, html_content)
                with open('mamadregex.txt', 'a') as mr:
                    for email in emails:
                        if email not in printed_emails:
                            printed_emails.add(email)
                            mr.write("email : " + email + '\n')
                    for phone in phones:
                        if phone not in printed_phones:
                            printed_phones.add(phone)
                            mr.write("phone : " + phone + '\n')
            except:
                pass

if __name__ == "__main__":
    reset_files()
    get_arguments()

    with open('subdomains.txt', 'r') as sub:
        subd = sub.read().splitlines()

    find_ports_and_ips()
    get_links()
    check_status_codes()
    find_subdomains()
    get_whois_info()
    regex_search()
