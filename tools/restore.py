import os
import requests
from zipfile import ZipFile


# Elastic or Opensearch
if os.getenv('REFLEX_ES_DISTRO') == 'opensearch':
    from opensearch_dsl import connections
else:
    from elasticsearch_dsl import connections


if __name__ == "__main__":
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

    print(es.indices.get('*'))