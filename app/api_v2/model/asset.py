"""app/api_v2/model/repassetort.py

Contains the models for asset inventory component of Reflex
"""

from . import (
    base,
    Keyword,
    Text,
    Boolean,
    Integer,
    Date,
)

class Asset(base.BaseDocument):

    asset_type = Keyword() # The type of asset (identity, group, computer)
    name = Keyword() # The name of the asset
    description = Keyword() # The description of the asset
    source_id = Keyword() # The unique ID of the asset (e.g. a Windows SID)
    source = Keyword() # The source of the asset (e.g. Active Directory)
    first_seen = Date() # The date the asset was first seen
    last_seen = Date() # The date the asset was last seen
    is_active = Boolean() # Is the asset active
    is_deleted = Boolean() # Is the asset deleted (this is a soft delete)
    owner = Keyword() # The owner of the asset (e.g. a user)
    service_account = Boolean() # Is the asset a service account
    member_of = Keyword() # The groups the asset is a member of
    os = Keyword() # The operating system of the asset
    os_version = Keyword() # The operating system version of the asset
    ips = Keyword() # The IP addresses of the asset
    macs = Keyword() # The MAC addresses of the asset
    mail = Keyword() # The email addresses of the asset
    phone = Keyword() # The phone numbers of the asset
    title = Keyword() # The title of the asset
