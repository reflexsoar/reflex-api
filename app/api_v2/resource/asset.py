import datetime

from flask_restx import Resource, Namespace, fields, inputs as xinputs

from .shared import mod_user_list, ISO8601
from ..utils import token_required, user_has

from ..model import (
    Asset,
    UserAsset,
    GroupAsset,
    ComputerAsset
)

from ..model.asset import VALID_ASSET_TYPES, VALID_USER_TYPES

api = Namespace('Asset', description="Asset operations", path="/asset")


mod_operating_system = api.model('OperatingSystem', {
    'name': fields.String(required=True),
    'version': fields.String(required=True),
    'arch': fields.String(required=False),
    'service_pack': fields.String(required=False),
    'build': fields.String(required=False),
    'language': fields.String(required=False),
}, strict=True)

mod_group_asset = api.model('GroupAsset', {
    'name': fields.String(required=True),
    'description': fields.String(required=False),
    'domain': fields.String(required=False),
    'distinguished_name': fields.String(required=False),
    'sid': fields.String(required=False),
    'members': fields.List(fields.String, required=False, default=[]),
}, strict=True)

mod_network_interface = api.model('NetworkInterface', {
    'name': fields.String(required=True),
    'description': fields.String(required=False),
    'mac': fields.String(required=False),
    'ip': fields.List(fields.String, default=[], required=False),
    'subnet': fields.String(required=False),
    'gateway': fields.String(required=False),
    'dns': fields.List(fields.String, default=[], required=False),
    'dhcp': fields.Boolean(required=False, default=False),
    'enabled': fields.Boolean(required=False, default=False)
}, strict=True)


mod_create_computer_asset = api.model('CreateComputerAsset', {
    'name': fields.String(required=True),
    'fqdn': fields.String(required=False),
    'interface': fields.List(fields.Nested(mod_network_interface, required=False, default=[])),
    'ip': fields.List(fields.String, required=False, default=[]),
    'mac': fields.List(fields.String, required=False, default=[]),
    'os': fields.Nested(mod_operating_system, required=False),
    'domain': fields.String(required=False),
    'distinguished_name': fields.String(required=False),
    'enabled': fields.Boolean(required=False, default=False),
    'last_logon': fields.String(required=False),
    'last_reboot': fields.String(required=False),
    'last_logon_user': fields.String,
    'owner': fields.String(required=False),
    'sid': fields.String(required=False),
    'serial_number': fields.String(required=False),
    'form_factor': fields.String(required=False),
}, strict=True)

mod_create_user_asset = api.model('CreateUserAsset', {
    'name': fields.String(required=True),
    'user_principal_name': fields.String(required=False),
    'first_name': fields.String(required=False),
    'last_name': fields.String(required=False),
    'email': fields.String(required=False),
    'phone': fields.String(required=False),
    'mobile': fields.String(required=False),
    'title': fields.String(required=False),
    'department': fields.String(required=False),
    'manager': fields.String(required=False),
    'location': fields.String(required=False),
    'enabled': fields.Boolean(required=False, default=False),
    'locked': fields.Boolean(required=False, default=False),
    'last_logon': fields.String(required=False),
    'user_type': fields.String(required=False),
    'domain': fields.String(required=False),
    'distinguished_name': fields.String(required=False),
    'sid': fields.String(required=False),
}, strict=True)

mod_user_asset = api.inherit('UserAsset', mod_create_user_asset, {
    'last_logon': ISO8601()
})

mod_computer_asset = api.inherit('ComputerAsset', mod_create_computer_asset, {
    'last_logon': ISO8601(),
    'last_reboot': ISO8601()
})

mod_asset_create = api.model('AssetCreate', {
    'asset_type': fields.String(required=True),
    'host': fields.Nested(mod_create_computer_asset, required=False),
    'user': fields.Nested(mod_create_user_asset, required=False),
    'group': fields.Nested(mod_group_asset, required=False),
    'tags': fields.List(fields.String, required=False),
    'note': fields.String(required=False),
}, strict=True)

mod_asset_detail = api.model('AssetDetail', {
    'uuid': fields.String,
    'asset_type': fields.String,
    'host': fields.Nested(mod_computer_asset, skip_none=True),
    'user': fields.Nested(mod_user_asset, skip_none=True),
    'group': fields.Nested(mod_group_asset, skip_none=True),
    'tags': fields.List(fields.String),
    'note': fields.String,
    'created_at': ISO8601(),
    'updated_at': ISO8601(),
    'created_by': fields.Nested(mod_user_list),
    'updated_by': fields.Nested(mod_user_list)
})

mod_asset_list = api.model('AssetList', {
    'assets': fields.List(fields.Nested(mod_asset_detail))
})

@api.route('/host/hostname/<string:hostname>')
class ComputerAssetDetailByHostname(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_asset_detail)
    @token_required
    @user_has('view_assets')
    def get(self, hostname, current_user):

        asset = Asset.get_by_host_name(hostname)
        if not asset:
            api.abort(404, 'Asset not found')
        return asset
    
@api.route('/host/ip/<string:ip>')
class ComputerAssetDetailByIP(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_asset_detail)
    @token_required
    @user_has('view_assets')
    def get(self, ip, current_user):

        asset = Asset.get_by_host_ip(ip)
        if not asset:
            api.abort(404, 'Asset not found')
        return asset


asset_list_parser = api.parser()
asset_list_parser.add_argument('asset_type', type=str, help='Asset type', location='args')
asset_list_parser.add_argument('tag', type=str, help='Tag', location='args')
asset_list_parser.add_argument('host__name', type=str, help='Host name', location='args')
asset_list_parser.add_argument('host__ip', type=str, help='IP address', location='args')
asset_list_parser.add_argument('mac', type=str, help='MAC address', location='args')
asset_list_parser.add_argument('user__username', type=str, help='User principal name', location='args')


@api.route('')
@api.doc(security="Bearer")
class AssetList(Resource):


    @api.marshal_with(mod_asset_list)
    @api.expect(asset_list_parser)
    @token_required
    @user_has('view_assets')
    def get(self, current_user):

        args = asset_list_parser.parse_args()

        search = Asset.search()

        for arg in args:
            if args[arg]:
                search = search.filter('term', **{arg: args[arg]})

        import json
        print(json.dumps(search.to_dict(), indent=4))

        assets = search.scan()
        return {'assets': [a for a in assets]}
    
    @api.expect(mod_asset_create)
    @api.marshal_with(mod_asset_detail)
    @token_required
    @user_has('create_asset')
    def post(self, current_user):

        asset_type_data_class = {
            'user': UserAsset,
            'host': ComputerAsset,
            'group': GroupAsset
        }

        if api.payload['asset_type'] not in VALID_ASSET_TYPES:
            api.abort(400, 'Invalid asset type')

        if api.payload['asset_type'] == 'user':
            api.payload.pop('host', None)
            api.payload.pop('group', None)

        if api.payload['asset_type'] == 'host':
            api.payload.pop('user', None)
            api.payload.pop('group', None)

        if api.payload['asset_type'] == 'group':
            api.payload.pop('user', None)
            api.payload.pop('host', None)

        asset_data = api.payload.pop(api.payload['asset_type'], None)
        if asset_data:
            asset_data_object = asset_type_data_class[api.payload['asset_type']](**asset_data)

        asset = Asset(**api.payload, **{api.payload['asset_type']: asset_data_object})

        # Grab all the IP addresses and MAC addresses from the interfaces and populate them
        # in to the ip and mac fields
        if asset.asset_type == 'host':
            for iface in asset.host.interface:
                if iface.ip:
                    if asset.host.ip:
                        asset.host.ip.extend(iface.ip)
                    else:
                        asset.host.ip = iface.ip
                if iface.mac:
                    if asset.host.mac:
                        asset.host.mac.append(iface.mac)
                    else:
                        asset.host.mac = [iface.mac]

        try:
            asset.save()
        except ValueError as e:
            api.abort(400, e)
        
        return asset, 201