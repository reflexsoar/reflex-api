from .integration import api as IntegrationApi
from .integration import IntegrationBase, IntegrationJob

# Dynamically import all the versions of the integrations
# for example app.integrations.reflexsoar.v1
# This will allow us to add new versions of the integration
# without having to update this file
import pkgutil
import inspect
import os
import sys

from .integration import integration_registry

__all__ = [
    'IntegrationApi',
    'IntegrationBase',
    'IntegrationJob',
    'integration_registry'
]

# Find the directory of the current file
dir_path = os.path.dirname(os.path.realpath(__file__))
# Find the directory of the integrations
integrations_path = os.path.join(dir_path, '..')
# Add the integrations directory to the path so we can import the integrations
sys.path.append(integrations_path)

loaded_integrations = {}

# Loop through all the integrations in the integrations directory
for _, name, _ in pkgutil.iter_modules([integrations_path]):
    # Import the integration
    integration = __import__(f"app.integrations.{name}", fromlist=[''])

    # Loop through all the modules in the integration
    for _, modname, _ in pkgutil.iter_modules([integration.__path__[0]]):
        # Import the module
        mod = __import__(f"app.integrations.{name}.{modname}", fromlist=[''])

        # Loop through all the classes in the module
        for _, cls in inspect.getmembers(mod, inspect.isclass):
            # If the class is a subclass of IntegrationBase
            if issubclass(cls, IntegrationBase):
                # Add the class to the __all__ list
                __all__.append(cls)

                # Add the class to the integrations dictionary
                loaded_integrations[name] = cls
