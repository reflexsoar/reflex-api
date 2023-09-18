import json
import requests_cache
from requests import Session

from app.integrations.base import IntegrationBase

class Guardicore(IntegrationBase):

    def action_label_asset(self):
        # Print the functions name
        """
        Labels an asset in Guardicore
        """
        print("action_label_asset")
        
    def action_remove_asset_label(self):
        """
        Removes a label from an asset
        """
        print("action_remove_asset_label")
        
    def action_run_insight_query(self):
        """
        Runs a Guardicore Insight query, which can be fetched later.
        The query can also be used to dynamically label assets.
        """
        
        print("action_run_insight_query")
        
    def action_poll_incidents(self):
        """
        Polls Guardicore incidents as new Reflex Events
        """
        
        print("action_poll_incidents")
        
    def action_get_assets_details(self):
        """
        Fetches asset details from Guardicore and 
        returns the results as a comment on the event. Will
        also push the entire integration output to integrations output
        """
        
        print("action_get_assets_details")
        
guardicore = Guardicore()
