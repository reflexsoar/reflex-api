# reflex-api

![coverage](coverage.svg) ![pep508](pep508.svg) ![vulnerable](vulnerable.svg)

## Development

1. Run `pipenv install`
2. Create `instance\application.conf` and provide the following 

```
MASTER_PASSWORD = "somethingdifferentthanthesecretkey"
SECRET_KEY = "pleasechangemetosomethingdifferent"
SECURITY_PASSWORD_SALT = "something_super_secret_change_in_production"
ELASTICSEARCH_URL = ['localhost:9200']
ELASTICSEARCH_USERNAME = "elastic"
ELASTICSEARCH_PASSWORD = "password"
```

3. Run `pipenv run python manage.py run` 

## 