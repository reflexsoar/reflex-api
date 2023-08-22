"""
Contains the models for SSO configurations
"""

from . import (
    base,
    Keyword,
    Text,
    Boolean
)


class SSOProvider(base.BaseDocument):

    name = Keyword(fields={'text': Text()})
    description = Text(fields={'keyword': Keyword()})
    enabled = Boolean()
    idp_cert = Text(fields={'keyword': Keyword()})
    idp_entity_id = Keyword()
    idp_signon_url = Keyword()
    idp_signout_url = Keyword()
    auto_provision_users = Boolean()
    default_role = Keyword()
    logon_domains = Keyword()
    acs_url = Keyword()
    slo_url = Keyword()
    active = Boolean()

    class Index:
        name = 'reflex-sso-providers'
        settings = {
            'refresh_interval': '1s'
        }

    @classmethod
    def name_exists(self, name):
        '''
        Checks to make sure the name of the realm is unique
        '''
        search = self.search()

        # Filter by the name
        search = search.filter('term', name=name)

        # Execute the search
        results = search.execute()

        # If we have results, return the first one
        if results:
            return True
        
        return False

    @classmethod
    def get_by_logon_domain(cls, logon_domain):
        '''
        Gets a realm by the logon domain
        '''
        search = cls.search()

        # Filter by the logon_domain
        search = search.filter('term', logon_domains=logon_domain)

        # Must be active
        search = search.filter('term', active=True)

        # Sort by created_at such that the earliest created is first
        search = search.sort({'created_at': {'order': 'asc'}})

        # Execute the search
        results = search.execute()

        # If we have results, return the first one
        if results:
            return results[0]

        return None
    
    def get_sso_settings(self):
        """
        Returns a dictionary of the SSO settings
        """
        settings = {
            "strict": False,
            "debug": True,
            "sp": {
                "entityId": "reflexsoar",
                "assertionConsumerService": {
                    "url": f"https://bc-dev-reflex.siemasaservice.com/api/v2.0/auth/sso/{self.uuid}/acs",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                },
                "singleLogoutService": {
                    "url": f"https://bc-dev-reflex.siemasaservice.com/api/v2.0/auth/sso/{self.uuid}/sls",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                "x509cert": "",
                "privateKey": ""
            },
            "idp": {
                "entityId": self.idp_entity_id,
                "singleSignOnService": {
                    "url": self.idp_signon_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "singleLogoutService": {
                    "url": self.idp_signout_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "x509cert": self.idp_cert
            }
        }

        return settings
