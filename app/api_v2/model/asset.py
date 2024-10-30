"""app/api_v2/model/asset.py

Contains the models for asset inventory component of Reflex
"""

from . import (
    base,
    Keyword,
    Text,
    Boolean,
    Integer,
    Date,
    Object,
    Nested,
    Ip
)

VALID_ASSET_TYPES = ['user','group','host']
VALID_USER_TYPES = ['local','domain','service','network','database']


class SoftwareAsset(base.InnerDoc):
    '''
    Defines all the attributes that would typically reside on a software asset
    '''

    name = Keyword() # The name of the software
    description = Keyword(fields={'text':Text()}) # The description of the software
    version = Keyword() # The version of the software
    publisher = Keyword() # The publisher of the software
    first_seen = Date() # The first time the software was seen
    last_seen = Date() # The last time the software was seen
    risk_modifier = Integer() # The risk modifier of the software
    sanctioned = Boolean() # Whether the software is sanctioned or not
    computer_name = Keyword() # The computer name of the software

    class Index:
        name = 'reflex-software-assets'
        settings = {
            'refresh_interval': '5s',
        }


class OperatingSystem(base.InnerDoc):
    '''Defines all the attributes that would typically reside on an operating system asset'''

    name = Keyword() # The name of the operating system
    version = Keyword() # The version of the operating system
    arch = Keyword() # The architecture of the operating system
    service_pack = Keyword() # The service pack of the operating system
    build = Keyword() # The build of the operating system
    language = Keyword() # The language of the operating system


class GroupAsset(base.InnerDoc):
    '''Defines all the attributes that would typically reside on a group asset'''

    name = Keyword() # The name of the group
    description = Keyword(fields={'text':Text()}) # The description of the group
    domain = Keyword() # The domain of the group
    distinguished_name = Keyword() # The distinguished name of the group
    sid = Keyword() # The SID of the group
    members = Keyword() # The members of the group


class UserAsset(base.InnerDoc):
    '''Defines all the attributes that would typically reside on a user asset'''

    name = Keyword() # The username of the user
    user_principal_name = Keyword() # The user principal name of the user
    first_name = Keyword() # The first name of the user
    last_name = Keyword() # The last name of the user
    email = Keyword() # The email address of the user
    phone = Keyword() # The phone number of the user
    mobile = Keyword() # The mobile number of the user
    title = Keyword() # The title of the user
    department = Keyword() # The department of the user
    manager = Keyword() # The manager of the user
    location = Keyword() # The location of the user
    enabled = Boolean() # Is the user enabled
    locked = Boolean() # Is the user locked
    last_logon = Date() # The date the user last logged on
    user_type = Keyword() # The type of user (e.g. local, domain, service)
    domain = Keyword() # The domain of the user
    distinguished_name = Keyword() # The distinguished name of the user
    sid = Keyword() # The SID of the user


class NetworkInterface(base.InnerDoc):
    '''Defines all the attributes that would typically reside on a network interface asset'''

    name = Keyword() # The name of the network interface
    description = Text() # The description of the network interface
    mac = Keyword() # The MAC address of the network interface
    ip = Ip() # The IP address of the network interface
    subnet = Keyword() # The subnet of the network interface
    gateway = Keyword() # The gateway of the network interface
    dns = Keyword() # The DNS of the network interface
    dhcp = Boolean() # Is the network interface configured via DHCP
    enabled = Boolean() # Is the network interface enabled


class ComputerAsset(base.InnerDoc):
    '''Defines all the attributes that would typically reside on a computer asset'''

    name = Keyword() # The hostname of the computer
    fqdn = Keyword() # The fully qualified domain name of the computer
    interface = Nested(NetworkInterface) # The network interfaces of the computer
    ip = Ip() # The IP address of the computer
    mac = Keyword() # The MAC address of the computer
    os = Object(OperatingSystem) # The operating system of the computer
    domain = Keyword() # The domain of the computer
    distinguished_name = Keyword() # The distinguished name of the computer
    enabled = Boolean() # Is the computer enabled
    last_logon = Date() # The date the computer last logged on
    last_reboot = Date() # The date the computer last rebooted
    last_logon_user = Keyword() # The last user to log on to the computer
    owner = Keyword() # The owner of the computer (e.g. a user)
    sid = Keyword() # The SID of the computer
    serial_number = Keyword() # The serial number of the computer
    form_factor = Keyword() # The form factor of the computer (e.g. laptop, desktop, server)


class Asset(base.BaseDocument):

    asset_type = Keyword() # The type of asset (e.g. user, computer)
    host = Object(ComputerAsset) # The computer asset
    user = Object(UserAsset) # The user asset
    group = Object(GroupAsset) # The group asset
    first_seen = Date() # The date the asset was first seen
    last_seen = Date() # The date the asset was last seen
    tags = Keyword() # The tags of the asset
    note = Text(fields={'keyword': Keyword()}) # The note of the asset

    class Index:
        name = 'reflex-assets'
        settings = {
            'refresh_interval': '5s',
        }

    def save(self, **kwargs):
        '''Override the save method to ensure only valid properties are saved'''

        if self.asset_type not in VALID_ASSET_TYPES:
            raise ValueError('Invalid asset type')
        
        if self.asset_type == 'user':
            if self.user.user_type not in VALID_USER_TYPES:
                raise ValueError('Invalid user type')
            
        return super(Asset, self).save(**kwargs)
    
    @classmethod
    def get_by_asset_type(cls, asset_type):
        '''Get all assets of a specific type'''

        if asset_type not in VALID_ASSET_TYPES:
            raise ValueError('Invalid asset type')
        
        return cls.search().filter('term', asset_type=asset_type)
    
    @classmethod
    def get_by_user_type(cls, user_type):
        '''Get all user assets of a specific type'''

        if user_type not in VALID_USER_TYPES:
            raise ValueError('Invalid user type')
        
        return cls.search().filter('term', user_type=user_type)
    
    @classmethod
    def get_by_sid(cls, sid):
        '''Get all assets with a specific SID'''

        return cls.search().filter('term', sid=sid)
    
    @classmethod
    def get_by_name(cls, name):
        '''Get all assets with a specific name'''

        return cls.search().filter('term', name=name)
    
    @classmethod
    def get_by_ip(cls, ip):
        '''Get all assets with a specific IP address'''

        return cls.search().filter('term', ip=ip)
    
    @classmethod
    def get_by_distinguished_name(cls, distinguished_name):
        '''Get all assets with a specific distinguished name'''

        return cls.search().filter('term', distinguished_name=distinguished_name)
    
    @classmethod
    def get_by_host_name(cls, host_name):
        '''Get all assets with a specific hostname'''

        result = cls.search().filter('term', host__name=host_name).execute()
        if result:
            return result[0]
        return None
    
    @classmethod
    def get_by_host_ip(cls, host_ip):
        '''Get all assets with a specific host IP address'''

        result = cls.search().filter('term', host__ip=host_ip).execute()
        if result:
            return result[0]
        return None
