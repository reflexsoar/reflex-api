import os
import json
from flask import make_response, render_template, current_app
from flask_restx import Resource, Namespace

api = Namespace('Release Notes', path='/release-notes', description='Release Notes')

parser = api.parser()

parser.add_argument('version', type=str, help='Version number', location='args', default='current')

@api.route("")
class ReleaseNotes(Resource):
    
    @api.expect(parser)
    def get(self):
        """Get release notes for a specific version"""

        args = parser.parse_args()

        current_version = current_app.config['BUILD_VERSION']

        if args.version == 'current':
            args.version = current_version

        version_file = f"{args.version}.json".lower()

        payload = {
            'notes': {},
            'previous_versions': []
        }
        
        # Find all the previous versions in the templates/release-notes folder
        template_path = os.path.join(current_app.root_path,
                                        current_app.template_folder,
                                        'release-notes'
                                    )
        versions = os.listdir(template_path)
        for ver in versions:
            if version_file == ver.lower():
                # If the file exists load it
                try:
                    with open(os.path.join(template_path, ver)) as f:
                        payload['notes'] = json.load(f)
                except Exception as e:
                    current_app.logger.error(f"Error loading release notes: {e}")

            payload['previous_versions'].append(ver.split('.json')[0].lower())

        # Remove the current_version from the previous versions list
        try:
            payload['previous_versions'].remove(current_version)
        except ValueError:
            pass

        # Sort the previous versions list alphabetically
        payload['previous_versions'].sort(reverse=True)

        return payload