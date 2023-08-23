"""
Contains the models for SSO configurations
"""

from flask import current_app
from . import (
    base,
    Keyword,
    Text,
    Boolean,
    InnerDoc,
    Object
)


class SSOAdvancedSecuritySettings(InnerDoc):

    name_id_encrypted = Boolean()
    authn_requests_signed = Boolean()
    logout_requests_signed = Boolean()
    logout_response_signed = Boolean()
    signin_metadata = Boolean()
    want_messages_signed = Boolean()
    want_assertions_signed = Boolean()
    want_name_id = Boolean()
    want_name_id_encrypted = Boolean()
    want_assertions_encrypted = Boolean()
    allow_single_label_domains = Boolean()
    signature_algorithm = Keyword()
    digest_algorithm = Keyword()
    reject_deprecated_algorithms = Boolean()
    want_attribute_statement = Boolean()


SECURITY_SETTINGS_MAPPING = {
    'name_id_encrypted': 'nameIdEncrypted',
    'authn_requests_signed': 'authnRequestsSigned',
    'logout_requests_signed': 'logoutRequestsSigned',
    'logout_response_signed': 'logoutResponseSigned',
    'signin_metadata': 'signMetadata',
    'want_messages_signed': 'wantMessagesSigned',
    'want_assertions_signed': 'wantAssertionsSigned',
    'want_name_id': 'wantNameId',
    'want_name_id_encrypted': 'wantNameIdEncrypted',
    'want_assertions_encrypted': 'wantAssertionsEncrypted',
    'allow_single_label_domains': 'allowSingleLabelDomains',
    'signature_algorithm': 'signatureAlgorithm',
    'digest_algorithm': 'digestAlgorithm',
    'reject_deprecated_algorithms': 'rejectDeprecatedAlgorithms',
    'want_attribute_statement': 'wantAttributeStatement'
}


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
    security = Object(SSOAdvancedSecuritySettings)

    class Index:
        name = 'reflex-sso-providers'
        settings = {
            'refresh_interval': '1s'
        }

    @classmethod
    def uuid_exists(self, uuid):
        '''
        Checks to make sure the uuid of the realm is unique
        '''
        search = self.search()

        # Filter by the uuid
        search = search.filter('term', uuid=uuid)

        # Execute the search
        results = search.execute()

        # If we have results, return the first one
        if results:
            return True
        
        return False
    
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
        
        sso_base_url = current_app.config['SSO_BASE_URL']

        
        """
        TODO: Load the privateKey and x509cert from a file path
        sso_private_key_path = current_app.config['SSO_PRIVATE_KEY_PATH']
        sso_x509cert_path = current_app.config['SSO_X509CERT_PATH']

        with open(sso_private_key_path, 'r') as f:
            sso_private_key = f.read()

        with open(sso_x509cert_path, 'r') as f:
            sso_x509cert = f.read()

        # Validate that these are x509 formatted
        try:
            x509.load_pem_x509_certificate(sso_x509cert.encode(), default_backend())
        except:
            raise ValueError("SSO x509cert is not a valid x509 certificate")
        """


        settings = {
            "strict": True,
            "debug": True,
            "sp": {
                "entityId": f"reflexsoar:sp:{self.uuid}:saml2",
                "assertionConsumerService": {
                    "url": f"{sso_base_url}/api/v2.0/auth/sso/{self.uuid}/acs",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                },
                "singleLogoutService": {
                    "url": f"{sso_base_url}/api/v2.0/auth/sso/{self.uuid}/sls",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                "x509cert": "",  # TODO: Load this from a file path
                "privateKey": ""  # TODO: Load this from a file path
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

        if hasattr(self, 'security'):
            settings['security'] = {}
            for key, value in SECURITY_SETTINGS_MAPPING.items():
                if hasattr(self.security, key):
                    settings['security'][value] = getattr(self.security, key)

        return settings
