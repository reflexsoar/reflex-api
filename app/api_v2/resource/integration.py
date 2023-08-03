import datetime

from flask_restx import Resource, Namespace, fields, inputs as xinputs

from .shared import mod_user_list, ISO8601, AsAttrDict, mod_run_action
from ..utils import token_required, user_has

from ..model.integration import IntegrationConfiguration, Integration
from ...integrations.base import integration_registry

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

mod_configured_action = api.model('ConfiguredAction', {
    'uuid': fields.String,
    'name': fields.String,
    'friendly_name': fields.String,
    'parameters': AsAttrDict,
    'integration_uuid': fields.String,
    'integration_name': fields.String,
    'configuration_uuid': fields.String,
    'configuration_name': fields.String
})

mod_configured_action_list = api.model('ConfiguredActionList', {
    'actions': fields.List(fields.Nested(mod_configured_action))
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


@api.route("/<string:uuid>/configurations/<string:config_uuid>/enable")
class IntegrationConfigActivation(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_integration_config_details)
    @token_required
    #@user_has('modify_integration_configuration')
    def post(self, current_user, uuid, config_uuid):
        """
        Activates an integration configuration
        """

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

        configuration = configuration[0]

        # Ensure the configuration belongs to the users organization unless
        # the current user is_default_org
        if not current_user.is_default_org and configuration.organization != current_user.organization:
            api.abort(403, "You do not have permission to enable this configuration")

        # Ensure that the configuration is not already active
        if configuration.enabled:
            api.abort(409, "Configuration is already enabled")

        # Activate the configuration
        configuration.enabled = True
        configuration.save(refresh=True)

        # Return the configuration
        return configuration


@api.route("/<string:uuid>/configurations/<string:config_uuid>/disable")
class IntegrationConfigActivation(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_integration_config_details)
    @token_required
    #@user_has('modify_integration_configuration')
    def post(self, current_user, uuid, config_uuid):
        """
        Activates an integration configuration
        """

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

        configuration = configuration[0]

        # Ensure the configuration belongs to the users organization unless
        # the current user is_default_org
        if not current_user.is_default_org and configuration.organization != current_user.organization:
            api.abort(403, "You do not have permission to disable this configuration")

        # Ensure that the configuration is not already active
        if not configuration.enabled:
            api.abort(409, "Configuration is already disabled")

        # Activate the configuration
        configuration.enabled = False
        configuration.save(refresh=True)

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
    
    @api.doc(security="Bearer")
    @api.marshal_with(mod_integration_config_details)
    @token_required
    #@user_has('delete_integration_configuration')
    def delete(self, current_user, uuid, config_uuid):
        """
        Deletes a single Integration Configuration
        """

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

        if hasattr(configuration,'enabled') and configuration.enabled:
            api.abort(409, "Cannot delete an enabled configuration")

        configuration = configuration[0]
        configuration.delete()

        return {}

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


@api.route("/run_action")
class RunActionResource(Resource):

    @api.doc(security='Bearer')
    @api.expect(mod_run_action)
    #@token_required
    #@user_has('run_action')
    def post(self):#, current_user):
        """
        Run an action against a set of events, cases, or observables
        """
        
        try:
            integration = integration_registry[api.payload['integration_uuid']]
        except KeyError:
            api.abort(400, "Integration not found")

        # TODO: Validate that any of the target objects are accessible by this user or
        # the integrations configuration organization

        try:
            integration.run_action(api.payload['action'],
                                   events=api.payload['events'],
                                   configuration_uuid=api.payload['configuration_uuid'],
                                   **api.payload['parameters'])
        except ValueError as e:
            api.abort(400, f"Action not found: {e}")
        except Exception as e:
            api.abort(400, f"Error running action: {e}")

    
actions_parser = api.parser()
actions_parser.add_argument('source_object_type', type=str, required=False, location='args', action="split")
actions_parser.add_argument('observable_type', type=str, required=False, location='args', action="split")
actions_parser.add_argument('trigger', type=str, required=False, location='args', default='manual')
    
@api.route("/configured_actions")
class ConfiguredActionsResource(Resource):

    @api.doc(security='Bearer')
    @api.marshal_with(mod_configured_action_list)
    @api.expect(actions_parser)
    @token_required
    #@user_has('view_integrations')
    def get(self, current_user):
        """
        Returns a list of all configured actions that support adhoc execution for all
        integrations.
        """

        # Parse the arguments
        args = actions_parser.parse_args()
        
        # Load all the integrations
        integrations = Integration.search().scan()

        configured_actions = []

        for integration in integrations:

            # Ensure that the integration configuration exists
            configurations = IntegrationConfiguration.search()
            configurations = configurations.filter('term', integration_uuid=integration.product_identifier)
            configurations = configurations.filter('term', organization=current_user.organization)

            # Only return enabled configurations
            configurations = configurations.filter('term', enabled=True)
            configurations = [c for c in configurations.scan()]

            # Retrieve the configured actions
            for config in configurations:
                for action in config.actions:
                    action_settings = config.actions[action]
                    if action_settings['enabled']:

                        action_manifest = integration.get_action_manifest(action)
                        
                        if 'trigger' in action_manifest and args.trigger not in action_manifest['trigger']:
                            continue

                        action_parameters = None
                        if 'parameters' in action_manifest:
                            action_parameters = action_manifest['parameters']

                        # Filter based on the args
                        if args.source_object_type:
                            
                            # If none of the source object types match, then skip
                            if not any([s in args.source_object_type for s in action_manifest['source_object_type']]):
                                continue

                        if args.observable_type:

                            # If none of the observable types match, then skip
                            if not any([s in args.observable_type for s in action_manifest['observable_types']]):
                                continue

                        configured_actions.append({
                            "name": action,
                            "friendly_name": action_manifest['friendly_name'],
                            "parameters": action_parameters,
                            "integration_uuid": integration.product_identifier,
                            "integration_name": integration.name,
                            "configuration_uuid": config.uuid,
                            "configuration_name": config.name
                        })

        return {
            "actions": configured_actions
        }
