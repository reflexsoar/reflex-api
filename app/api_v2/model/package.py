"""app/api_v2/model/package.py

Contains the models for package management component of Reflex. Package Management
allows agents to install, manage, and remove software packages on a host.
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
    Ip,
    Binary
)

class PackageTypes(enumerate):

    CUSTOM = 'custom'
    SYSMON = 'sysmon'
    WINLOGBEAT = 'winlogbeat'
    FILEBEAT = 'filebeat'
    VECTOR = 'vector'

class Package(base.BaseDocument):
    """
    Packages define the software that can be installed, managed, and removed by the
    agent.  Packages should be stand alone and not require installation as a service
    or daemon.  
    """

    package_type = Keyword(fields={'text': Text()}) # The type of package
    name = Keyword(fields={'text': Text()}) # The name of the package
    filename = Keyword(fields={'text': Text()}) # The filename of the package
    version = Keyword(fields={'text': Text()}) # The version of the package
    description = Keyword(fields={'text': Text()}) # The description of the package
    package_data = Binary() # The package data
    checksum = Keyword(fields={'text': Text()}) # The package hash
    start_command = Keyword(fields={'text': Text()}) # The command to launch the package
    stop_command = Keyword(fields={'text': Text()}) # The command to stop the package
    install_command = Keyword(fields={'text': Text()}) # The command to install the package
    uninstall_command = Keyword(fields={'text': Text()}) # The command to uninstall the package
    variables = Nested() # The variables for the package

    class Index:
        name = 'reflex-packages'
        settings = {
            'refresh_interval': '5s',
        }
