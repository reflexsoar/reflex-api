from . import (
    Keyword,
    base,
    Object,
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
