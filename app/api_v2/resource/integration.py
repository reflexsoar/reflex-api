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
    'brief_description': fields.String,
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
    'product_identifier': fields.String,
    'license_name': fields.String,
})

mod_integration_config_details = api.model('IntegrationConfigDetails', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'enabled': fields.Boolean(default=False),
    'integration_uuid': fields.String,
    'actions': AsAttrDict,
    'global_settings': AsAttrDict,
    'created_at': ISO8601,
    'created_by': fields.Nested(mod_user_list),
    'updated_at': ISO8601,
    'updated_by': fields.Nested(mod_user_list),
})

mod_create_integration_config = api.model('CreateIntegrationConfig', {
    'name': fields.String,
    'description': fields.String,
    'enabled': fields.Boolean(default=False),
    'actions': AsAttrDict,
    'global_settings': AsAttrDict
})

mod_integration_config_list = api.model('IntegrationConfigList', {
    'configurations': fields.List(fields.Nested(mod_integration_config_details))
})

mod_integration_list = api.model('IntegrationList', {
    'integrations': fields.List(fields.Nested(mod_integration_details))
})

@api.route("/<string:uuid>/configurations")
class IntegrationConfigList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_integration_config_list)
    @token_required
    #@user_has('view_integrations')
    def get(self, current_user, uuid):
        """
        List available integrations
        Requires the `view_integrations` permission
        """

        # Retrieves a list of available integrations
        configurations = IntegrationConfiguration.search()
        configurations = configurations.filter('term', integration_uuid=uuid)
        configurations = configurations.scan()

        response = {
            'configurations': [c for c in configurations]
        }

        return response
    
    @api.doc(security="Bearer")
    @api.marshal_with(mod_integration_config_details)
    @api.expect(mod_create_integration_config)
    @token_required
    #@user_has('create_integration_configuration')
    def post(self, current_user, uuid):
        """
        Create a new integration configuration
        Requires the `create_integration_configuration` permission
        """

        # Ensure that the integration exists
        integration = Integration.get(uuid=uuid)
        if not integration:
            api.abort(404, "Integration not found")

        # Ensure that a configuration with the same name for the integration
        # does not exist
        existing_config = IntegrationConfiguration.search()
        existing_config = existing_config.filter('term', integration_uuid=uuid)

        if current_user.is_default_org and 'organization' in api.payload:
            existing_config = existing_config.filter('term', organization=api.payload['organization'])
        else:
            existing_config = existing_config.filter('term', organization=current_user.organization)

        existing_config = existing_config.filter('term', name=api.payload['name'])
        existing_config = existing_config.execute()

        # If the configuration contains no actions that are enabled, then
        # we should not allow the configuration to be created
        if not any([a['enabled'] for a in api.payload['actions'].values()]):
            api.abort(400, "Configuration must contain at least one enabled action")

        if existing_config:
            api.abort(409, "Configuration with the same name already exists")

        # Create the configuration
        configuration = IntegrationConfiguration(
            name=api.payload['name'],
            enabled=True,
            integration_uuid=uuid,
            actions=api.payload['actions'],
            global_settings=api.payload['global_settings'],
        )
        configuration.save()

        # Return the configuration
        return configuration


@api.route("/<string:uuid>/configurations/<string:config_uuid>")
class IntegrationConfigDetailResource(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_integration_config_details)
    @token_required
    #@user_has('view_integration_configuration')
    def get(self, current_user, uuid, config_uuid):
        """
        Fetches the details of a single Integration Configuration
        """

        pass

    @api.doc(security="Bearer")
    @api.marshal_with(mod_integration_config_details)
    @api.expect(mod_create_integration_config)
    @token_required
    #@user_has('modify_integration_configuration')
    def put(self, current_user, uuid, config_uuid):
        """
        Updates a single Integration Configuration
        """

        # If the configuration contains the organization parameter and 
        # it is different from the current_users organization, reject the 
        # request, unless the user is_default_org
        if 'organization' in api.payload:
            if api.payload['organization'] != current_user.organization and not current_user.is_default_org:
                api.abort(403, "Cannot modify configuration for another organization")

        # Ensure that the integration exists
        integration = Integration.get(uuid=uuid)
        if not integration:
            api.abort(404, "Integration not found")

        # Ensure the configuration exists
        configuration = IntegrationConfiguration.search()
        configuration = configuration.filter('term', uuid=config_uuid)
        configuration = configuration.filter('term', integration_uuid=uuid)
        configuration = configuration.execute()

        if not configuration:
            api.abort(404, "Configuration not found")

        # Ensure a configuration by the same name does not exist for the same
        # organization
        existing_config = IntegrationConfiguration.search()
        existing_config = existing_config.filter('term', integration_uuid=uuid)

        if current_user.is_default_org and 'organization' in api.payload:
            existing_config = existing_config.filter('term', organization=api.payload['organization'])
        else:
            existing_config = existing_config.filter('term', organization=current_user.organization)

        existing_config = existing_config.filter('term', name=api.payload['name'])
        existing_config = existing_config.execute()

        if existing_config and existing_config[0].uuid != config_uuid:
            api.abort(409, "Configuration with the same name already exists")

        # If the configuration contains no actions that are enabled, then
        # we should not allow the configuration to be updated
        if not any([a['enabled'] for a in api.payload['actions'].values()]):
            api.abort(400, "Configuration must contain at least one enabled action")

        # Update the configuration
        configuration = configuration[0]
        configuration.update(**api.payload)
        
        return configuration

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

    @api.doc(security="Bearer")
    @api.marshal_with(mod_integration_details)
    @token_required
    @user_has('view_integrations')
    def get(self, current_user, uuid):
        """
        Get details for an integration.
        Requires the `view_integrations` permission
        """

        # Retrieves the integration details so that a user can configure
        # the integration
        integration = Integration.get(uuid=uuid)

        if not integration:
            api.abort(404, "Integration not found")

        # Requires the user to have `view_integrations`
        # permissions

        return integration

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