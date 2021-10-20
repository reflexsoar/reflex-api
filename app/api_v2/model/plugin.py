from . import (
    base,
    Text,
    Object,
    Boolean,
    Keyword
)

class Plugin(base.BaseDocument):
    '''
    Plugins are used to interact with external systems and extend
    the functionality of reflex
    '''

    name = Text()
    description = Text()
    manifest = Object()
    config_template = Object()
    enabled = Boolean()
    filename = Text()
    file_hash = Text()
    configs = Keyword()

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-plugins'

    @property
    def config_count(self):
        '''
        Returns how many configurations are associated
        with this plugin
        '''
        if self.configs:
            return len(self.configs)
        return 0

    def add_config(self, config):
        '''
        Adds a reference to a configuration item
        '''
        if self.configs:
            self.configs.append(config.uuid)
        else:
            self.configs = [config.uuid]
        self.save()


class PluginConfig(base.BaseDocument):
    '''
    Each Plugin can have multiple configurations
    A PluginConfig contains each unique configuration for a plugin
    '''

    name = Text()
    description = Text()
    config = Object()

    class Index: # pylint: disable=too-few-public-methods
        ''' Defines the index to use '''
        name = 'reflex-plugin-configs'
