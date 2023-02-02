from urllib.request import urlopen
from bs4 import BeautifulSoup
import requests_cache
from cvss_trans import *

base_url = "https://nvd.nist.gov/vuln/detail/cve-"

requests_cache.install_cache('html_cache')

def retrieve_html_information(url, beacon, attr, attr_value): # TODO - We can optimize this function by using lxml
	html_page   = urlopen(url)
	html_parse  = BeautifulSoup(html_page, 'html.parser') 
	result      = html_parse.select_one(f"{beacon}[{attr}='{attr_value}']")
	return result.get_text() 


def get_cve_info(cve_number): # TODO - Add threads to retrieve informations
    url = base_url + cve_number
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


cve_info = get_cve_info("2016-5195")

for value in cve_info.values():
    if "CVSS" in value:
        print(convert_to_detailed_cvss(value))