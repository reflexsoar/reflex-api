import requests_cache
from requests import Session
from app.integrations.base import IntegrationBase


class Opensearch(IntegrationBase):

    def action_test(self):
        print("HELLO WORLD THIS IS A TEST ACTION")


opensearch = Opensearch()
