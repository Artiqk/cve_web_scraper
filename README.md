## Install the requirements
```
python3 -m pip install -r requirements.txt
```
## How to use
### In order to filter your CVEs properly, you will need to use the parameters from the RedHat Security Data API: <br>
https://access.redhat.com/documentation/en-us/red_hat_security_data_api/1.0/html/red_hat_security_data_api/cve#parameters_2
### Example
```
python3 cve_web_scraper.py before=2016-03-01 after=2016-02-01 per_page=10
```
This will retrieve all the CVEs after 1st February 2016 and before 1st March 2016 and it will display only 10 CVEs.
## Disclaimer: Do not abuse with the number of CVE per page
