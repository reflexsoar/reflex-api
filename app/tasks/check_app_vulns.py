""" Contains application code related to the discovery of active CVEs and
other vulnerabilities for applications installed on agents in the system.

Functions:

    * check_app_vulns - Checks for vulnerabilities in applications installed on
        agents in the system.
    * curate_app_vulns - Curates the list of vulnerabilities for applications
        installed on agents in the system.  If there is a vulnerability entry
        that no longer applies to any applications, it is removed.
"""
import requests


from app.api_v2.model.application import ApplicationInventory, ApplicationVulnerability

def check_app_vulns(app):
    """
    Takes the CPE of an application and checks for vulnerabilities in the
    local database.  """

    # Get all the applications and then check them against the NVD
    # API to see if there are any vulnerabilities

    search = ApplicationInventory.search()
    results = search.scan()

    # Dedupe the list of applications by application_signature so that
    # we don't check the same application multiple times for multiple
    # organizations
    applications = {}
    for result in results:
        if result.application_signature not in applications:
            applications[result.application_signature] = result

    # Now that we have a list of applications, check them against the
    # NVD API to see if there are any vulnerabilities
    for application in applications:
        # Get the application
        app = applications[application]

        cpeName = [c for c in app.cpes if ':a:' in c][0]

        if 'Wireshark' in app.name:

            print(cpeName)

            # Check the NVD API for vulnerabilities
            url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpeName}'
            response = requests.get(url)
            if response.status_code == 200:
                # We got a response, so parse it
                data = response.text
                print(data)