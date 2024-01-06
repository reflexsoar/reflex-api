from hashlib import sha1 

from . import (
    Keyword,
    base,
    Object,
    Boolean
)

class ApplicationInventory(base.BaseDocument):

    agent = Object(
        properties={
            'name': Keyword(),
            'uuid': Keyword()
        }
    )
    name = Keyword()  # The name of the software package
    version = Keyword()  # The version of the software package
    vendor = Keyword()  # The vendor of the software package
    identifying_number = Keyword()  # The identifying number of the software package
    install_date = Keyword()  # The install date of the software package
    install_source = Keyword()  # The install source of the software package
    local_package = Keyword()  # The local package of the software package
    package_cache = Keyword()  # The package cache of the software package
    package_code = Keyword()  # The package code of the software package
    package_name = Keyword()  # The package name of the software package
    url_info_about = Keyword()  # The URL info about of the software package
    language = Keyword()  # The language of the software package
    application_signature = Keyword()  # The hash of the software package, which is a combination of the name, version, and vendor
    deleted = Boolean()
    
    class Index:
        name = 'reflex-application-inventory'
        settings = {
            'refresh_interval': '5s',
        }

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
            cls(**application).save()

    @classmethod
    def compute_signature(cls, name, version, vendor):
        '''
        Computes the application signature
        '''

        _signature = f"{name}{version}{vendor}"

        return sha1(_signature.encode('utf-8')).hexdigest()

    def save(self, **kwargs):
        '''
        Save the document
        '''

        _signature = f"{self.name}{self.version}{self.vendor}"

        self.application_signature = sha1(_signature.encode('utf-8')).hexdigest()

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

        _signature = f"{self.name}{self.version}{self.vendor}"

        self.application_signature = sha1(_signature.encode('utf-8')).hexdigest()

        # pylint: disable=arguments-differ
        return super().update(**kwargs)

