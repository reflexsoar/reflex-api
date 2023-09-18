"""
Consumes JSON feeds of Microsoft Infrastructure domains and IPs

https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20230904.json

https://download.microsoft.com/download/0/1/8/018E208D-54F8-44CD-AA26-CD7BC9524A8C/PublicIPs_20200824.xml
https://download.microsoft.com/download/B/2/A/B2AB28E1-DAE1-44E8-A867-4987FE089EBE/msft-public-ips.csv
"""
import requests_cache
from requests import Session
from app.integrations.base import IntegrationBase


class MicrosoftInfrastructureFeeds(IntegrationBase):

    def fetch_microsoft_ips(self, url):
        '''
        Pulls down the Microsoft IP JSON List
        '''
        s = Session()
        result = s.get(url)
        if result.status_code == 200:
            return result.json()
        else:
            raise Exception('Unable to fetch IP information from Microsoft')
        
    def get_ips_by_url(self, data: list, urls: list) -> list:
        '''
        Retreives all the IPS from a service area based on the URLs in the service
        area
        '''
        ips = []

        # Type checking
        if not isinstance(data, list):
            raise ValueError('{data} is not a Dict')
        if not isinstance(urls, list):
            raise ValueError("URLs {urls} is not a List")

        else:
            for url in urls:
                if not isinstance(url, str):
                    raise ValueError("Service Area {sa} is not a String")

                for entry in data:
                    if 'urls' in entry and url in entry['urls']:
                        if 'ips' in entry and isinstance(entry['ips'], list):
                            ips += entry['ips']
        return ips
    
    def get_ips_by_service_area(self, data: list, service_areas: list) -> list:
        '''
        Retrieves all the IPs from the defined Service Area
        '''
        ips = []

        # Type checking
        if not isinstance(data, list):
            raise ValueError('{data} is not a Dict')
        if not isinstance(service_areas, list):
            raise ValueError("Service Areas {service_areas} is not a List")

        else:
            for sa in service_areas:
                if not isinstance(sa, str):
                    raise ValueError("Service Area {sa} is not a String")

                for entry in data:
                    if 'serviceAreaDisplayName' in entry and entry['serviceAreaDisplayName'] == sa:
                        if 'ips' in entry and isinstance(entry['ips'], list):
                            ips += entry['ips']

        return ips


    def sync_office365_service_assets(self):
        '''
        Syncs the IPs from the Microsoft Infrastructure Feed
        https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7
        '''

        # Check to see if the Intel List has been created and if not create it
        
        pass


    def action_test(self):
        print("HELLO WORLD THIS IS A TEST ACTION")


microsoft_infrastructure_feeds = MicrosoftInfrastructureFeeds()
