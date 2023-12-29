import datetime
import ipaddress
import math
import random
import string
from functools import lru_cache

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ..model import Agent, Detection, Tag, UpdateByQuery


def generate_random_password(length=32):
    '''
    Generates a random password
    '''
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))


def generate_private_key(key_type='ec', key_size=2048):
    '''
    Generates an ECDSA private key and returns it in PEM format
    '''

    if key_type == 'ec':

        private_key = ec.generate_private_key(
            ec.SECP256R1(), default_backend())
        
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
    
    elif key_type == 'rsa':

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
    
    else:
        return None


def derive_public_key(private_key, key_type):
    '''
    Derives the public key from the private key
    '''

    try:

        if key_type == 'ec':
            private_key = serialization.load_pem_private_key(
                private_key.encode(),
                password=None,
                backend=default_backend()
            )

            public_key = private_key.public_key()

            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        
        elif key_type == 'rsa':                
                private_key = serialization.load_pem_private_key(
                    private_key.encode(),
                    password=None,
                    backend=default_backend()
                )
    
                public_key = private_key.public_key()
    
                return public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
        else:
            return None
        
    except Exception as e:
        return None


def time_since(start_time, message, format="s"):
    '''
    Prints the time since the start_time in the format
    '''
    time_diff = datetime.datetime.utcnow() - start_time
    if format == "s":
        print(f"{message} - {time_diff.total_seconds()}s")
    elif format == "ms":
        print(f"{message} - {time_diff.total_seconds()*1000}ms")
    elif format == "h":
        print(f"{message} - {time_diff.total_seconds()/3600}h")
    return time_diff


@lru_cache(maxsize=10000)
def check_ip_whois_io(ip):
    ''' Connects to ipwhois.io and pulls information about the IP address'''

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {}

    ip_information = {}
    try:
        r = requests.get(f'https://ipwho.is/{ip}')
        if r.status_code == 200:
            ip_information = r.json()
    except:
        pass
    return ip_information


def save_tags(tags):
    '''
    Adds tags to a reference index that the UI uses for 
    suggesting reasonable tags to the user
    '''

    for tag in tags:
        _tag = Tag.get_by_name(name=tag)
        if not _tag:
            tag = Tag(name=tag)
            tag.save()


def chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i + n]


def redistribute_detections(organization=None):
    '''
    When the following criteria is true this function will redistribute the detection workload
    of all agents in the given organization

    If a new detection is added
    If a detection is disabled or deleted
    If an agent is added or its health changes to unhealthy
    '''
    agents = Agent.get_by_organization(organization)
    detections = Detection.get_by_organization(organization)

    # If there are agents
    if len(agents) > 0:

        # Filter for agents that are detectors
        agents = [
            agent for agent in agents if agent.merged_roles and 'detector' in agent.merged_roles and agent.healthy]
        if len(agents) > 0:

            detection_sets = []

            # Distribute the agents across all the detections
            if len(detections) > 0:
                detection_sets = list(
                    chunks(detections, math.ceil(len(detections)/len(agents))))

            for i in range(0, len(detection_sets)):

                # Fix for slow agent redistribution, looping through each
                # detection was a bottleneck
                uuids = [detection.uuid for detection in detection_sets[i]]

                update_by_query = UpdateByQuery(index=Detection._index._name)
                update_by_query = update_by_query.filter("terms", uuid=uuids)
                update_by_query = update_by_query.script(
                    source=f"ctx._source.assigned_agent = '{agents[i].uuid}'"
                )

                # Wait for a refresh to make sure the changes are available for the next function
                update_by_query.params(
                    refresh=True, slices="auto", wait_for_completion=True)

                update_by_query.execute()

        else:

            update_by_query = UpdateByQuery(index=Detection._index._name)
            update_by_query = update_by_query.filter(
                "term", organization=organization)
            update_by_query = update_by_query.script(
                source="ctx._source.assigned_agent = null"
            )

            # Wait for a refresh to make sure the changes are available for the next function
            update_by_query.params(
                refresh=True, slices="auto", wait_for_completion=True)

            update_by_query.execute()
