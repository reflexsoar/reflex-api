''' /app/upgrades.py
Handles very specific upgrade tasks.
'''
from concurrent.futures import ThreadPoolExecutor

from app.api_v2.model.threat import ThreatList
from app.api_v2.model.detection import Detection
from app.api_v2.model.credential import Credential

def set_required_fields_on_detections(app):
    """ Find all detections that do not have the required fields set
    and set them
    """

    def update_detection(detection):
        detection.extract_fields_from_query()
        if detection.required_fields is not None:
            print(
                f"Setting required fields on detection {detection.name} ({detection.uuid})")
            detection.save()

    detections = [d for d in Detection.search().filter('term', from_repo_sync=False).scan()
                  if not hasattr(d, 'required_fields') or d.required_fields is None]
    if len(detections) > 0:
        print(f"Setting required fields on {len(detections)} detections")

        with ThreadPoolExecutor(max_workers=10) as executor:
            for detection in detections:
                executor.submit(update_detection, detection)


def migrate_all_threshold_configs_to_list_keys(app):
    """ Find all threshold rules where key_field is a string
    and turn it into a list
    """

    # Find all where threshold_config.key_field is a string
    detections = [d for d in Detection.search().filter(
        'bool', must={'exists': {'field': 'threshold_config.key_field'}}).scan()]

    if len(detections) > 0:

        print('Migrating threshold configs to list keys...')
        for d in detections:
            if isinstance(d.threshold_config.key_field, str):
                d.threshold_config.key_field = [d.threshold_config.key_field]
                d.save(refresh=True)

        _detections = [d for d in Detection.search().filter(
            'bool', must={'exists': {'field': 'threshold_config.key_field'}}).scan()]
        if len(_detections) == 0:
            print('Migration complete')


def migrate_intel_list_data_feeds_to_static_names(app):

    # find all lists that dont currently have the data_type_name field set
    # and set it to the correct value based on the data_type field

    # Find all where data_type_name does not exist
    lists = [l for l in ThreatList.search().filter(
        'bool', must_not={'exists': {'field': 'data_type_name'}}).scan()]

    if len(lists) > 0:
        print('Migrating intel lists to static names...')
        for l in lists:
            l.data_type_name = l.data_type.name
            l.save(refresh=True)

        _lists = [l for l in ThreatList.search().filter(
            'bool', must_not={'exists': {'field': 'data_type_name'}}).scan()]
        if len(_lists) == 0:
            print('Migration complete')



def migrate_credentials_hmac(app):
    """ Ugrades all the credentials to use SHA512 HMAC """

    credentials = Credential.search().scan()

    for credential in credentials:
        credential.encrypt(message=credential.decrypt(app.config['MASTER_PASSWORD'], alg="sha256").encode(),
                           secret=app.config['MASTER_PASSWORD'],
                           alg="sha512")

    print('Credential migration complete')

upgrades = [
    #migrate_intel_list_data_feeds_to_static_names,
    #migrate_all_threshold_configs_to_list_keys
    #set_required_fields_on_detections
    #migrate_credentials_hmac
]