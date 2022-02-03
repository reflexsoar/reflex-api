# reflex-api 

![coverage](coverage.svg) ![pep508](pep508.svg) ![vulnerable](vulnerable.svg)

## Development

1. Run `pipenv install`
2. Create `instance\application.conf` and provide the following 

```
MASTER_PASSWORD = "somethingdifferentthanthesecretkey"
SECRET_KEY = "pleasechangemetosomethingdifferent"
SECURITY_PASSWORD_SALT = "something_super_secret_change_in_production"
```

3. Run `pipenv run python manage.py run` 

## Getting Started

### Docker

```
version: '3.7'

services:
  reflex-api:
    environment:
      - REFLEX_ES_URL=es01:9200
      - REFLEX_ES_USERNAME=elastic
      - REFLEX_ES_PASSWORD=password
      - REFLEX_ES_CA=/ca.crt
      - REFLEX_ES_CERT_VERIFY=true
      - REFLEX_RECOVERY_MODE=false
    image: zeroonesec/reflex-api:elastic-backend
    container_name: reflex-api
    volumes:
      - ./application.conf:/instance/application.conf
      - ./ca.crt:/ca.crt

  reflex-ui:
    image: zeroonesec/reflex-ui:elastic-migration
    container_name: reflex-ui
    ports:
      - 80:80
      - 443:443
```

1. Create a new file called `application.conf`
2. Add the following entries and change the values
  ```
  MASTER_PASSWORD = "somethingdifferentthanthesecretkey"
  SECRET_KEY = "pleasechangemetosomethingdifferent"
  SECURITY_PASSWORD_SALT = "something_super_secret_change_in_production"
  ```
3. Change `REFLEX_ES_URL` to the hostnames of your Elasticsearch cluster
4. Change `REFLEX_ES_USERNAME` and `REFLEX_ES_PASSWORD`
5. Optional, supply a CA cert if connecting to Elasticsearch over TLS
6. Optional, set `REFLEX_ES_CERT_VERIFY=true` to make sure certs are valid
7. Bring the containers up
8. Run `docker exec reflex-api sh -c "pipenv run python setup.py"` to perform initial setup
8. Navigate to https://localhost
9. Login as admin@reflexsoar.com\reflex
