from urllib.request import urlopen
from bs4 import BeautifulSoup
import requests_cache
import requests
from cvss_trans import *

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


def get_cve_info(cve_id): # TODO - Add threads to retrieve informations
    url = base_url + cve_id
    published_on = retrieve_html_information(url, "span", "data-testid", "vuln-published-on")
    vector = retrieve_html_information(url, "span", "data-testid", "vuln-cvss3-nist-vector")
    description = retrieve_html_information(url, "p", "data-testid", "vuln-description")
    cve_score = retrieve_html_information(url, "a", "data-testid", "vuln-cvss3-panel-score")
    return {
        "published_on": published_on, 
        "cvss": vector, 
        "description": description, 
        "score": cve_score
    }


def convert_to_detailed_cvss(cvss):
    cvss = cvss.split('/')[1:]
    detailed_cvss = {}
    for vector in cvss:
        name, score = vector.split(':')
        score = cvss_score[name][score]
        name = cvss_titles[name]
        detailed_cvss[name] = score
    return detailed_cvss


def get_cve_list_from_filter(url):
    response = requests.get(redhat_url)
    html_parse = BeautifulSoup(response.content, 'lxml')
    return [cve.get_text().lower() for cve in html_parse.findAll('b')]


def export_cve_info(cve):
    cve_info = get_cve_info(cve)
    for value in cve_info.values():
        if "CVSS" in value:
            print(convert_to_detailed_cvss(value))
        else:
            print(value)
    print("======================================================================================")



redhat_url = "https://access.redhat.com/hydra/rest/securitydata/cve?after=2022-01-01&before=2023-01-01&severity=important&per_page=2"

cves = get_cve_list_from_filter(redhat_url)

for cve in cves:
    export_cve_info(cve)