import json
import random
import datetime
import hashlib
import base64
import requests

host = 'http://localhost'

def auth():
    response = requests.post('{}/api/v1.0/auth/login'.format(host),
                             data=json.dumps({'username':'admin@reflexsoar.com', 'password':'reflex'}),
                             headers={'Content-Type': 'application/json'})
    if response.status_code == 200:
        token = response.json()['access_token']
        return token
    else:
        return None


def bulk(events):

    token = auth()
    if token:
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer '+token
        }
        response = requests.post('{}/api/v1.0/event/_bulk'.format(host),
                                 data=json.dumps({"events": events}),
                                 headers=headers)
        if response.status_code == 200:
            print(response.json())
        else:
            print(response.content)
    else:
        return events
    
def reference():
    hasher = hashlib.md5()
    hasher.update(str(random.randint(0,1000)+datetime.datetime.utcnow().timestamp()).encode())
    return base64.b64encode(hasher.digest()).decode()

events = []
for i in range(0,15):
    event = {
      "title": "From API for Load Testing 7",
      "reference": reference(),
      "description": "This alert was generated via load testing",
      "tags": [
        "string"
      ],
      "tlp": 0,
      "severity": 0,
      "observables": [
        {
          "value": "brian-pc",
          "ioc": False,
          "tlp": 0,
          "spotted": False,
          "safe": False,
          "dataType": "host",
          "tags": [
            "source-ip"
          ]
        },
        {
          "value": "brian",
          "ioc": False,
          "tlp": 0,
          "spotted": False,
          "safe": False,
          "dataType": "user",
          "tags": [
            "source-user"
          ]
        },
        {
          "value": "127.0.0.1",
          "ioc": False,
          "tlp": 0,
          "spotted": False,
          "safe": False,
          "dataType": "ip",
          "tags": [
            "source-ip"
          ]
        }
      ],
      "raw_log": "string"
    }

    events.append(event)
print(len(events))
bulk(events)