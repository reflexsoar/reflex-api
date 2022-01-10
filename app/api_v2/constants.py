"""
./app/api_v2/constants.py

Contains constant values that are referenced in the API
"""

DATA_TYPES = [
    'ip',
    'domain',
    'fqdn',
    'host',
    'email',
    'email_subject',
    'md5hash',
    'sha1hash',
    'sha256hash',
    'user',
    'command',
    'url',
    'imphash',
    'process',
    'sid',
    'mac',
    'detection_id',
    'port',
    'filepath',
    'generic'
]

# Used to translate SIDS in to human readible format via tags
MS_SID_ENDS_WITH = ends_with = {
    '500': 'Administrator',
    '501': 'Guest',
    '502': 'krbtgt',
    '512': 'Domain Admins',
    '513': 'Domain Users',
    '514': 'Domain Guests',
    '515': 'Domain Computers',
    '516': 'Domain Controllers',
    '517': 'Cert Publishers',
    '518': 'Schema Admins',
    '519': 'Enterprise Admins',
    '520': 'Group Policy Creator Owners',
    '553': 'RAS AND IAS Servers',
    '544': 'Administrators',
    '545': 'Users',
    '546': 'Guest',
    '547': 'Power Users',
    '548': 'Account Operators',
    '549': 'Server Operators',
    '550': 'Print Operators',
    '551': 'Backup Operators',
    '552': 'Replicators',
    '554': 'Builtin\\Pre-Windows 2000 Compatible Access',
    '555': 'Builtin\\Remote Desktop Users',
    '556': 'Builtin\\Network Configuration Operators',
    '557': 'Builtin\\Incoming Forest Trust Builders',
    '558': 'Builtin\\Performance Monitor Users',
    '559': 'Builtin\\Performance Log Users',
    '560': 'Builtin\\Windows Authorization Access Group',
    '561': 'Builtin\\Terminal Server License Servers',
    '562': 'Builtin\\Distributed COM Users',
    '569': 'Builtin\\Cryptographic Operators',
    '573': 'Builtin\\Event Log Readers',
    '574': 'Builtin\\Certificate Service DCOM Access',
    '575': 'Builtin\\RDS Remote Access Servers',
    '576': 'Builtin\\RDS Endpoint Servers',
    '577': 'Builtin\\RDS Management Servers',
    '578': 'Builtin\\Hyper-V Administrators',
    '579': 'Builtin\\Access Control Assistance Operators',
    '580': 'Builtin\\Remote Management Users'
}

# Used to translate SIDS in to human readible format via tags
MS_SID_EQUALS = {
    'S-1-5-64-10': 'NTLM Authentication',
    'S-1-5-64-14': 'SChannel Authentication',
    'S-1-5-64-21': 'Digest Authentication',
    'S-1-16-0': 'Untrusted Mandatory Level',
    'S-1-16-4096': 'Low Mandatory Level',
    'S-1-16-8192': 'Medium Mandatory Level',
    'S-1-16-8448': 'Medium Plus Mandatory Level',
    'S-1-16-12288': 'High Mandatory Level',
    'S-1-16-16384': 'System Mandatory Level',
    'S-1-16-20480': 'Protected Process Mandatory Level',
    'S-1-16-28672': 'Secure Process Mandatory Level'
}
