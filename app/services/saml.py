from flask import Blueprint
from flask_saml2.sp import ServiceProvider

class MyServiceProvider(ServiceProvider):
    def get_default_login_return_url(self):
        return 'ok'

    def get_logout_return_url(self):
        return 'logout'

sp = MyServiceProvider()