from hashlib import sha256 

from . import (
    Keyword,
    base,
    Object,
    Boolean,
    bulk,
    Date,
    Float,
    Nested
)

class CVSSMetrics(base.BaseDocument):

    version = Keyword()  # The CVSS version, e.g 2.0, 3.0, 3.1
    vector_string = Keyword()  # The CVSS vector string
    attack_vector = Keyword()  # The CVSS attack vector
    attack_complexity = Keyword()  # The CVSS attack complexity
    privileges_required = Keyword()  # The CVSS privileges required
    user_interaction = Keyword()  # The CVSS user interaction
    scope = Keyword()  # The CVSS scope
    confidentiality_impact = Keyword()  # The CVSS confidentiality impact
    integrity_impact = Keyword()  # The CVSS integrity impact
    availability_impact = Keyword()  # The CVSS availability impact
    base_score = Float()  # The CVSS base score
    base_severity = Keyword()  # The CVSS base severity
    exploitability_score = Float()  # The CVSS exploitability score
    impact_score = Float()  # The CVSS impact score

class ApplicationVulnerability(base.BaseDocument):

    cve = Keyword()  # The CVE of the vulnerability
    published = Date()
    lastModified = Date()
    vulnStatus = Keyword()
    description = Keyword()
    references = Nested(properties={
        'source': Keyword(),
        'url': Keyword(),
        'tags': Keyword()
    })

class AgentApplicationInventory(base.BaseDocument):
    """
    An index containing a link between agents and applications using
    the applications application_signature field
    """

    agent = Object(
        properties={
            'name': Keyword(),
            'uuid': Keyword()
        }
    )
    name = Keyword()  # The name of the software package
    version = Keyword()  # The version of the software package
    vendor = Keyword()  # The vendor of the software package
    application_signature = Keyword()  # The application signature
    identifying_number = Keyword()  # The identifying number of the software package
    install_date = Keyword()  # The install date of the software package
    install_source = Keyword()  # The install source of the software package
    local_package = Keyword()  # The local package of the software package
    package_cache = Keyword()  # The package cache of the software package
    package_code = Keyword()  # The package code of the software package
    package_name = Keyword()  # The package name of the software package
    url_info_about = Keyword()  # The URL info about of the software package
    language = Keyword()  # The language of the software package
    platform = Keyword()  # The platform the software package is installed on (windows, linux, macos, etc)

    class Index:
        name = 'reflex-agent-application-inventory'
        settings = {
            'refresh_interval': '1s',
        }

    @classmethod
    def delete_by_agent_and_application_sig(cls, agent_uuid: str, application_signatures: list):
        '''
        Deletes an agent application inventory item by agent and application signature
        '''
        try:
            cls.search().filter('term', agent__uuid=agent_uuid).filter('terms', application_signature=application_signatures).delete()
        except Exception as e:
            print(e)
            return
        
    @classmethod
    def bulk(cls, items: list):
        '''
        Bulk adds application inventory data
        '''
        _items = []
        for item in items:
            if isinstance(item, dict):
                _items.append(cls(**item).to_dict(True))
            else:
                _items.append(item.to_dict(True))

        bulk(cls._get_connection(), (i for i in _items))


class ApplicationInventory(base.BaseDocument):

    name = Keyword()  # The name of the software package
    version = Keyword()  # The version of the software package
    vendor = Keyword()  # The vendor of the software package
    application_signature = Keyword()  # The hash of the software package, which is a combination of the name, version, and vendor
    platform = Keyword()  # The platform the software package is installed on (windows, linux, macos, etc)
    is_vulnerable = Boolean()  # Whether or not the software package is vulnerable
    cpes = Keyword()  # Contains a list of CPEs for this software package
    
    class Index:
        name = 'reflex-application-inventory'
        settings = {
            'refresh_interval': '1s',
        }

    @property
    def vendor_shortname(self):
        '''
        Returns the vendor shortname for the application, which is just the
        first part of the vendor string (e.g. Microsoft, Inc. -> Microsoft)
        lowercased
        '''

        return self.vendor.split(' ')[0].lower()

    def _compute_cpes(self):
        '''
        Returns the CPE for the application
        '''

        PLATFORM_VENDOR_MAP = {
            'windows': 'microsoft',
            'linux': 'linux',
            'macos': 'apple'
        }

        _platform = self.platform.lower()
        if _platform not in PLATFORM_VENDOR_MAP:
            return []
        _os_vendor = PLATFORM_VENDOR_MAP[_platform]

        self.cpes = [
            f"cpe:2.3:a:{self.vendor_shortname}:{self.name.lower()}:{self.version}",
            f"cpe:2.3:o:{_os_vendor}:{_platform}:-"
        ]

    @classmethod
    def _bulk(cls, items: list):
        '''
        Bulk adds application inventory data
        '''
        _items = []
        for item in items:
            if isinstance(item, dict):
                _items.append(cls(**item).to_dict(True))
            else:
                _items.append(item.to_dict(True))

        bulk(cls._get_connection(), (i for i in _items))

    @classmethod
    def bulk_add(cls, agent, applications):
        '''
        Bulk adds application inventory data
        '''

        '''
        try:
            # Find all the existing applications for this agent
            existing_applications = cls.search().filter('term', agent__uuid=agent.uuid).scan()

            # Update any existing applications that have changed
            bulk_updates = []
            for application in applications:
                _existing_application = next((x for x in existing_applications if x.identifying_number == application['identifying_number']), None)
                if _existing_application:
                    if cls.compute_signature(application['name'], application['version'], application['vendor']) != _existing_application.application_signature:
                        bulk_updates.append({
                            '_op_type': 'update',
                            '_index': cls.Index.name,
                            '_type': cls._doc_type.name,
                            '_id': _existing_application.meta.id,
                            'doc': application
                        })

            # Update existing applications that no longer exist with deleted=True
            for application in existing_applications:
                if application.identifying_number not in [x['identifying_number'] for x in applications]:
                    bulk_updates.append({
                        '_op_type': 'update',
                        '_index': cls.Index.name,
                        '_type': cls._doc_type.name,
                        '_id': application.meta.id,
                        'doc': {
                            'deleted': True
                        }
                    })

            # Bulk update the applications
            if len(bulk_updates) > 0:
                cls.bulk(bulk_updates)
        except Exception:
            return

        # For new applications, add them one at a time
        for application in applications:
            _existing_application = next((x for x in existing_applications if x.identifying_number == application['identifying_number']), None)
            if not _existing_application:
                cls(
                    agent={'name': agent.name, 'uuid': agent.uuid},
                    name=application['name'],
                    version=application['version'],
                    vendor=application['vendor'],
                    identifying_number=application['identifying_number'],
                    install_date=application['install_date'],
                    install_source=application['install_source'],
                    local_package=application['local_package'],
                    package_cache=application['package_cache'],
                    package_code=application['package_code'],
                    package_name=application['package_name'],
                    url_info_about=application['url_info_about'],
                    language=application['language'],
                    deleted=False
                ).save()
        '''

        # Remove all existing application inventory data for this agent
        try:
            cls.search().filter('term', agent__uuid=agent.uuid).delete()
        except Exception:
            return
        
        for application in applications:
            application['agent'] = {
                'name': agent.name,
                'uuid': agent.uuid
            }
            application['organization'] = agent.organization
        
        cls._bulk(applications)

    @classmethod
    def compute_signature(cls, name: str, version: str, vendor: str, platform: str):
        '''
        Computes the application signature
        '''

        _signature = f"{name}:{vendor}:{version}:{platform}".lower()

        return sha256(_signature.encode('utf-8')).hexdigest()

    def save(self, **kwargs):
        '''
        Save the document
        '''

        if self.application_signature is None:
            self.application_signature = self.compute_signature(self.name, self.version, self.vendor, self.platform)
        if self.cpes is None:
            self.cpes = self._compute_cpes()

        # pylint: disable=arguments-differ
        return super().save(**kwargs)
    
    def update(self, **kwargs):
        '''
        Update the document
        '''

        if 'name' in kwargs:
            self.name = kwargs['name']
        if 'version' in kwargs:
            self.version = kwargs['version']
        if 'vendor' in kwargs:
            self.vendor = kwargs['vendor']

        if self.application_signature is None:
            self.application_signature = self.compute_signature(self.name, self.version, self.vendor, self.platform)
        if self.cpes is None:
            self.cpes = self._compute_cpes()

        # pylint: disable=arguments-differ
        return super().update(**kwargs)
