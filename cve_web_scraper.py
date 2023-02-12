from urllib.request import urlopen
from bs4 import BeautifulSoup
import requests_cache, requests, threading, sys
from cvss_trans import *
from openpyxl import Workbook
from openpyxl.styles import Border, Side, Alignment

base_url = "https://nvd.nist.gov/vuln/detail/"

requests_cache.install_cache('html_cache')

def retrieve_html_information(url, beacon, attr='', attr_value='', find_all=False):
    try:
        html_page   = urlopen(url)
        html_parse  = BeautifulSoup(html_page, 'lxml')
        if find_all:
            result = html_parse.findAll(beacon, {attr: attr_value})
            return result
        else:
            result = html_parse.select_one(f"{beacon}[{attr}='{attr_value}']") # p[data-testid='description']
            return result.get_text() 
    except: # FIXME - Add better error handling
        print("An error occured while trying to retrieve information on the page")
        return ""


def get_specific_links_in_page(cve_number, domain_to_retrieve): 
    url = base_url + str(cve_number)
    links = retrieve_html_information(url, "a", find_all=True, href=True)
    links_retrieved = []
    for element in links :
        link = element.get_text()
        if domain_to_retrieve in link: 
            links_retrieved.append(link)
    return links_retrieved


def get_cve_info(cve_id): # TODO - Add threads to retrieve informations
    url = base_url + cve_id
    cve_id = cve_id.split("cve-")[1]
    try:
        published_on = retrieve_html_information(url, "span", "data-testid", "vuln-published-on")
        description = retrieve_html_information(url, "p", "data-testid", "vuln-description")
        cvss_score, severity = retrieve_html_information(url, "a", "data-testid", "vuln-cvss3-panel-score").split(' ')
        return {
        "cve": cve_id,
        "published_on": published_on, 
        "description": description, 
        "severity": severity,
        "cvss_score": cvss_score
    }
    except:
        print("Error while parsing HTML")
        return {}


def get_cve_list_from_filter(url):
    response = requests.get(redhat_url)
    if response.status_code != 200:
        print("Incorrect arguments.")
        exit(0)
    html_parse = BeautifulSoup(response.content, 'lxml')
    return [cve.get_text().lower() for cve in html_parse.findAll('b')]


def export_cve_info(cve, worksheet, row):
    x = 0
    cve_info = get_cve_info(cve)
    for value in cve_info.values():
        cell = coords_to_excel(x, row)
        worksheet[cell] = value
        worksheet[cell].border = Border(
            top=Side(border_style='thin'),
            bottom=Side(border_style='thin'),
            right=Side(border_style='thin'),
            left=Side(border_style='thin'),
        )
        worksheet[cell].alignment = Alignment(
            horizontal='center',
            vertical='center',
            wrapText=True
        )
        x += 1


def coords_to_excel(x, y):
    excel_x = chr(x + 65)
    excel_y = y + 1
    return f"{excel_x}{excel_y}"


def create_table_header(worksheet, titles):
    x = 0
    for element in titles:
        cell = coords_to_excel(x, 0)
        worksheet[cell] = element
        worksheet[cell].border = Border(
            top=Side(border_style='thick'),
            bottom=Side(border_style='thick'),
            right=Side(border_style='thick'),
            left=Side(border_style='thick'),
        )
        worksheet[cell].alignment = Alignment(
            horizontal='center',
            vertical='center',
            wrapText=True
        )
        if element == "DESCRIPTION":
            worksheet.column_dimensions[cell[0]].width = 120
        x += 1

workbook = Workbook()
worksheet = workbook.active

titles = ["CVE", "DATE", "DESCRIPTION", "SEVERITY", "CVSS SCORE"]

redhat_url = "https://access.redhat.com/hydra/rest/securitydata/cve?page=1"

for i in range(1, len(sys.argv)):
    redhat_url += f"&{sys.argv[i]}"

if "per_page" not in redhat_url:
    redhat_url += "&per_page=50"

cves = get_cve_list_from_filter(redhat_url)

create_table_header(worksheet, titles)

row = 1

cve_threads = []

for cve in cves:
    t = threading.Thread(target=export_cve_info, args=(cve, worksheet, row))
    cve_threads.append(t)
    row += 1

for thread in cve_threads:
    thread.start()

for thread in cve_threads:
    thread.join()

workbook.save("cve_result.xlsx")   