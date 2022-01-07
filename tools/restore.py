import os
import json
import time
import requests
import logging
#import pyminizip
from zipfile import ZipFile
import argparse

# Elastic or Opensearch
if os.getenv('REFLEX_ES_DISTRO') == 'opensearch':
    from opensearch_dsl import connections, Document
else:
    from elasticsearch_dsl import connections, Document

REFLEX_VERSION = ''

class Event(Document):
    class Index:
        name = f'reflex-events{REFLEX_VERSION}'

class Tag(Document):
    class Index:
        name = f'reflex-tags{REFLEX_VERSION}'

class ExpiredToken(Document):
    class Index:
        name = f'reflex-expired-tokens{REFLEX_VERSION}'

class Credential(Document):
    class Index:
        name = f'reflex-credentials{REFLEX_VERSION}'

class Agent(Document):
    class Index:
        name = f'reflex-agents{REFLEX_VERSION}'

class ThreatList(Document):
    class Index:
        name = f'reflex-threat-lists{REFLEX_VERSION}'

class EventStatus(Document):
    class Index:
        name = f'reflex-event-statuses{REFLEX_VERSION}'

class EventRule(Document):
    class Index:
        name = f'reflex-event-rules{REFLEX_VERSION}'

class CaseComment(Document):
    class Index:
        name = f'reflex-case-comments{REFLEX_VERSION}'

class CaseHistory(Document):
    class Index:
        name = f'reflex-case-history{REFLEX_VERSION}'

class Case(Document):
    class Index:
        name = f'reflex-cases{REFLEX_VERSION}'

class CaseTask(Document):
    class Index:
        name = f'reflex-case-tasks{REFLEX_VERSION}'

class CaseTemplate(Document):
    class Index:
        name = f'reflex-case-templates{REFLEX_VERSION}'

class Observable(Document):
    class Index:
        name = f'reflex-observables-test{REFLEX_VERSION}'

class AgentGroup(Document):
    class Index:
        name = f'reflex-agent-groups{REFLEX_VERSION}'

class TaskNote(Document):
    class Index:
        name = f'reflex-case-task-notes{REFLEX_VERSION}'

class Plugin(Document):
    class Index:
        name = f'reflex-plugins{REFLEX_VERSION}'

class PluginConfig(Document):
    class Index:
        name = f'reflex-plugin-configs{REFLEX_VERSION}'

class EventLog(Document):
    class Index:
        name = f'reflex-audit-logs{REFLEX_VERSION}'

class User(Document):
    class Index:
        name = f'reflex-users{REFLEX_VERSION}'

class Role(Document):
    class Index:
        name = f'reflex-user-roles{REFLEX_VERSION}'

class DataType(Document):
    class Index:
        name = f'reflex-data-types{REFLEX_VERSION}'

class CaseStatus(Document):
    class Index:
        name = f'reflex-case-statuses{REFLEX_VERSION}'

class CloseReason(Document):
    class Index:
        name = f'reflex-close-reasons{REFLEX_VERSION}'

class Settings(Document):
    class Index:
        name = f'reflex-settings{REFLEX_VERSION}'


if __name__ == "__main__":

    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument('--archive_path','-a', type=str)
    parser.add_argument('--archive_password','-p', type=str)
    parser.add_argument('--dump','-d', action='store_true')
    parser.add_argument('--outfile', '-o', type=str)
    parser.add_argument('--nozip', action='store_true')

    args = parser.parse_args()

    ES_URL = os.getenv('REFLEX_ES_URL') if os.getenv('REFLEX_ES_URL') else ['localhost:9200']
    ES_USERNAME = os.getenv('REFLEX_ES_USERNAME') if os.getenv('REFLEX_ES_USERNAME') else 'admin'
    ES_PASSWORD = os.getenv('REFLEX_ES_PASSWORD') if os.getenv('REFLEX_ES_PASSWORD') else 'admin'
    ES_AUTH_SCHEME = os.getenv('REFLEX_ES_AUTH_SCHEMA') if os.getenv('REFLEX_ES_AUTH_SCHEMA') else 'http'
    ES_CA = os.getenv('REFLEX_ES_CA') if os.getenv('REFLEX_ES_CA') else None
    ES_CERT_VERIFY = os.getenv('REFLEX_ES_CERT_VERIFY') if os.getenv('REFLEX_ES_CERT_VERIFY') else False
    ES_USE_SSL = os.getenv('REFLEX_ES_USE_SSL') if os.getenv('REFLEX_ES_USE_SSL') else True
    ELASTICSEARCH_SHOW_SSL_WARN = True if os.getenv('REFLEX_ES_SHOW_SSL_WARN') else False # This can equal any value, as long as it is set True

    elastic_connection = {
        'hosts': ES_URL,
        'verify_certs': ES_CERT_VERIFY,
        'use_ssl': ES_AUTH_SCHEME,
        'ssl_show_warn': ELASTICSEARCH_SHOW_SSL_WARN
    }

    if ES_AUTH_SCHEME == 'http':
            elastic_connection['http_auth'] = (ES_USERNAME,ES_PASSWORD)

    elif ES_AUTH_SCHEME == 'api':
        elastic_connection['api_key'] = (ES_USERNAME,ES_PASSWORD)

    if ES_CA:
        elastic_connection['ca_certs'] = ES_CA

    connections.create_connection(**elastic_connection)

    es = connections.get_connection()

    if not args.archive_password and not args.nozip:
            logging.error('Password required')
            exit(1)

    models = [
        Event,Tag,ExpiredToken,Credential,Agent,ThreatList,EventStatus,EventRule,
        CaseComment,CaseHistory,Case,CaseTask,CaseTemplate,Observable,AgentGroup,
        TaskNote,Plugin,PluginConfig,EventLog,User,Role,DataType,CaseStatus,CloseReason,
        Settings
    ]

    if args.dump and not args.nozip:
        if not args.outfile:
            logging.error('Outfile name required')
            exit(1)        

        backup_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'backup\\')

        logging.info('Dumping reflex data to zip file')

        if not os.path.exists(backup_path):
            os.makedirs(backup_path)

        for f in os.listdir(backup_path):
                os.remove(os.path.join(backup_path, f))

        time.sleep(5)
        
        for model in models:

            filename = f'{model.Index.name}.json'
            file_path = os.path.join(backup_path, filename)
            search = model.search()
            search = search[0:search.count()]
            results = search.execute()
            results = [r.to_dict() for r in results]
            with open(file_path, 'w') as fout:
                json.dump(results, fout, default=str)

            if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
                logging.error(f'Failed to backup {filename}')

            if not args.nozip:
                files_to_zip = []
                for folderName, subfolders, filenames in os.walk(backup_path):
                    for filename in filenames:
                        if filename.endswith('.json'):
                            filepath = os.path.join(folderName,filename)
                            files_to_zip.append(filepath)

                #pyminizip.compress_multiple(files_to_zip, [], os.path.join(backup_path, args.outfile), args.archive_password, 9)

    else:

        if not args.archive_path and not args.nozip:
            logging.error('Archive path required')
            exit(1)

        backup_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'backup\\')

        logging.info('Restoring reflex data')

        for folderName, subfolders, filenames in os.walk(backup_path):
            for filename in filenames:
                if filename.endswith('.json'):
                    index_name = '.'.join(filename.split('.')[:-1])
                    filepath = os.path.join(folderName,filename)
                    with open(filepath, 'r') as fin:
                        
                        data = fin.read()
                        for model in models:
                            if model.Index.name == index_name:
                                for _ in json.loads(data):
                                    doc = model(**_)
                                    doc.save()

        time.sleep(5)