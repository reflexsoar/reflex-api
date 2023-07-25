import datetime

from flask_restx import Resource, Namespace, fields, inputs as xinputs

from .shared import mod_user_list, ISO8601, AsAttrDict
from ..utils import token_required, user_has

from ..model.integration import IntegrationConfiguration, Integration

api = Namespace('Integration', description="Integration operations", path="/integration")

mod_integration_details = api.model('IntegrationDetails', {
    'uuid': fields.String,
    'name': fields.String,
    'manifest': AsAttrDict,
    'description': fields.String,
    'created_at': ISO8601,
    'created_by': fields.Nested(mod_user_list),
    'modified_at': ISO8601,
    'modified_by': fields.Nested(mod_user_list),
    'author': fields.String,
    'contributor': fields.List(fields.String),
    'enabled': fields.Boolean(default=False),
    'version': fields.String,
    'logo': fields.String,
    'tags': fields.List(fields.String, default=[]),
    'category': fields.List(fields.String, default=[]),
})

mod_integration_config_details = api.model('IntegrationConfigDetails', {
    'uuid': fields.String,
    'name': fields.String,
    'integration_uuid': fields.String,
    'configuration': AsAttrDict,
    'created_at': ISO8601,
    'created_by': fields.Nested(mod_user_list),
    'modified_at': ISO8601,
    'modified_by': fields.Nested(mod_user_list),
})

mod_integration_list = api.model('IntegrationList', {
    'integrations': fields.List(fields.Nested(mod_integration_details))
})

@api.route("")
class IntegrationList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_integration_list)
    @token_required
    #@user_has('view_inputs')
    def get(self, current_user):
        """
        List available integrations
        Requires the `view_integrations` permission
        """

        # Retrieves a list of available integrations
        integrations = Integration.search().scan()

        response = {
            'integrations': [i for i in integrations]
        }

        return response

    def post(self):
        """
        Create a new integration
        Requires the `create_integration` permission and must be a member
        of the default tenant
        """
        pass


@api.route("/<string:uuid>")
class IntegrationDetails(Resource):

    def get(self):
        """
        Get details for an integration.
        Requires the `view_integrations` permission
        """

        # Retrieves the integration details so that a user can configure
        # the integration

        # Requires the user to have `view_integrations`
        # permissions

        pass

    def put(self):
        """
        Update an integration
        Requires the `update_integrations` permission and must be a member
        of the default tenant
        """

        # Only the Global Administrator can update an integration

        pass

    def delete(self):
        """
        Delete an integration
        Requires the `delete_integration` permission and must be a member
        of the default tenant
        """

        # Can not delete an integration if an existing configuration exists
        # for the specific integration

        # Only the Global Administrator can delete an integration
        pass

@api.route("/<string:uuid>/new_configuration")
class IntegrationConfigurationResource(Resource):

    @api.marshal_with(mod_integration_config_details)
    def post(self, uuid):
        """
        Create a new configuration for an integration
        Requires the `create_integration_configuration`
        """

        configuration = {
            "name": "Test Event Webhook",
            "integration_uuid": uuid,
            "configuration": {
                "ip_restrictions": ['127.0.0.1'],
                "user_agent_restrictions": []
            }
        }

        # Create a new configuration for the integration
        config = IntegrationConfiguration(**configuration)
        config.save()

        return config