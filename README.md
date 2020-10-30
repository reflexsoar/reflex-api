# reflex-api

![coverage](coverage.svg) ![pep508](pep508.svg) ![vulnerable](vulnerable.svg)

## Development

1. Run `pipenv install`
2. Create `instance\application.conf` and provide the following 

```
MASTER_PASSWORD = "somethingdifferentthanthesecretkey"
SECRET_KEY = "pleasechangemetosomethingdifferent"
SECURITY_PASSWORD_SALT = "something_super_secret_change_in_production"
DB_USERNAME='reflex'
DB_PASSWORD='reflex'
DB_HOST='localhost'
DB_PORT=3306
DB_NAME='reflex'
```

3. Run `pipenv run python manage.py run` 