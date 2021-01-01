from elasticsearch_dsl import connections
from app.api_v2.models import User

connections.create_connection(hosts=['localhost:9200'], use_ssl=True, verify_certs=False, http_auth=('elastic','URWsI66IP6qBYj6yr1L7'))

user_content = {
    'username': 'Admin',
    'email': 'admin@reflexsoar.com',
    'password': 'reflex',
    'first_name': 'Super',
    'last_name': 'Admin'
}

User.init()

user_password = user_content.pop('password')
user = User(**user_content)
user.set_password(user_password)
print(user.__dict__)
user.save()