from urllib.request import urlopen
from bs4 import BeautifulSoup
from cvss_trans import *

base_url = "https://nvd.nist.gov/vuln/detail/cve-"

def retrieve_html_information(url, beacon, attr, attr_value):
	html_page = urlopen(url) # On ouvre la page html et on la stock dans la variable
	html_parse = BeautifulSoup(html_page, 'html.parser') # Instancie un object BeautifulSoup qui permet de parser du HTML grâce à html.parser
	result =  html_parse.findAll(beacon, {attr: attr_value}) # Récupère les lignes HTML qui possèdes ces attribues
	return result[0].get_text() # Retourne le resultat sans les balises


def get_cve_info(cve_number): # TODO - Add threads to retrieve informations
    url = base_url + cve_number
    published_on = retrieve_html_information(url, "span", "data-testid", "vuln-published-on")
    vector = retrieve_html_information(url, "span", "data-testid", "vuln-cvss3-nist-vector")
    description = retrieve_html_information(url, "p", "data-testid", "vuln-description")
    cve_score = retrieve_html_information(url, "a", "data-testid", "vuln-cvss3-panel-score")
    return published_on, vector, description, cve_score, # FIXME - Put this in a dictionary


# published_on, vector, description, cve_score = get_cve_info("2016-5195")
# print(cve_score)

# ####### T'occupes pas #######

# def get_detailed_vector(vector):
#     vectors = vector.split('/')
#     vectors.pop(0)
#     for vector in vectors:
        
# detailed_vector = get_detailed_vector(vector)