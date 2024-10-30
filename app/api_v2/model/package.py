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

    name = Keyword(fields={'text': Text()})
    description = Keyword(fields={'text': Text()})
    version = Keyword(fields={'text': Text()})
    source = Keyword(fields={'text': Text()})
    source_checksum = Keyword(fields={'text': Text()})
    install_command = Keyword(fields={'text': Text()})
    uninstall_command = Keyword(fields={'text': Text()})
    install_working_directory = Keyword(fields={'text': Text()})
    install_timeout = Integer()
    configuration_source = Keyword(fields={'text': Text()})
    configuration_destination = Keyword(fields={'text': Text()})
    config_checksum = Keyword(fields={'text': Text()})
    start_command = Keyword(fields={'text': Text()})
    stop_command = Keyword(fields={'text': Text()})
    reconfigure_command = Keyword(fields={'text': Text()})
    dependencies = Keyword(fields={'text': Text()})

    class Index:
        name = 'reflex-packages'
        settings = {
            'refresh_interval': '5s',
        }
