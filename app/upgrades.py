''' /app/upgrades.py
Handles very specific upgrade tasks.
'''

from app.api_v2.model.threat import ThreatList


def migrate_intel_list_data_feeds_to_static_names():

    # find all lists that dont currently have the data_type_name field set
    # and set it to the correct value based on the data_type field

    # Find all where data_type_name does not exist
    lists = [l for l in ThreatList.search().filter('bool', must_not={'exists': { 'field': 'data_type_name'}}).scan()]
    
    if len(lists) > 0:
        print('Migrating intel lists to static names...')
        for l in lists:
            l.data_type_name = l.data_type.name
            l.save(refresh=True)

        _lists = [l for l in ThreatList.search().filter('bool', must_not={'exists': { 'field': 'data_type_name'}}).scan()]
        if len(_lists) == 0:
            print('Migration complete')


upgrades = [
    migrate_intel_list_data_feeds_to_static_names
]
