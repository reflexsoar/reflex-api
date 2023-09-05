"""
Defines an integration loader that continuously loads integrations from the
integrations directory.

Files are hashed and compared to the previous hash to determine if the file
has changed. If the file has changed, the file is reloaded.
"""

import hashlib
import pathlib
import pkgutil
import inspect
import os
import sys

from .integration import IntegrationBase
from app.api_v2.model.integration import Integration

loaded_integrations = {}
loaded_classes = []


def load_integrations():
    """
    Loads all JSON files from the integrations folder and converts
    them to Integration objects.  If the integration already exists
    it will skip it.
    """

    # Walk the integrations folder and get a list of all the JSON files
    # that are in the folder, the files can be in subfolders as well.

    manifest_files = []

    ipath = pathlib.Path('app/integrations')

    for integration_file in ipath.rglob("*.json"):
        manifest_files.append(integration_file)

    # For each JSON file, load the JSON file and convert it to an Integration
    # object.  If the integration already exists, skip it.
    for manifest_file in manifest_files:

        # Validate the JSON is valid
        try:
            Integration.load_manifest(manifest_file)
        except Exception as e:
            print(f'Error loading {manifest_file} - {e}')
            continue


def register_integrations():

    print("Loading integrations...")

    # Find the directory of the current file
    dir_path = os.path.dirname(os.path.realpath(__file__))
    # Find the directory of the integrations
    integrations_path = os.path.join(dir_path, '..')
    # Add the integrations directory to the path so we can import the integrations
    sys.path.append(integrations_path)

    # Loop through all the integrations in the integrations directory
    for _, name, _ in pkgutil.iter_modules([integrations_path]):
        # Import the integration
        integration = __import__(f"app.integrations.{name}", fromlist=[''])

        # Loop through all the modules in the integration
        for _, modname, _ in pkgutil.iter_modules([integration.__path__[0]]):
            # Import the module
            mod = __import__(
                f"app.integrations.{name}.{modname}", fromlist=[''])

            # Loop through all the classes in the module
            for _, cls in inspect.getmembers(mod, inspect.isclass):
                # If the class is a subclass of IntegrationBase
                if issubclass(cls, IntegrationBase):
                    
                    if cls not in loaded_classes:
                        # Add the class to the __all__ list
                        loaded_classes.append(cls)

                        # Add the class to the integrations dictionary
                        loaded_integrations[name] = cls

    print(f"Loaded {len(loaded_classes)} integrations")
    load_integrations()
