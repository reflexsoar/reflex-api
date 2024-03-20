import json
import datetime
import hashlib
import base64
import requests
import time
import random
import socket
import struct
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor

host = 'http://localhost'

AUTH_TOKEN = None

CONSOLE = sys.argv[1]
USERNAME = sys.argv[2]
PASSWORD = sys.argv[3]
EVENT_COUNT = int(sys.argv[4])

def auth():
    response = requests.post('{}/api/v2.0/auth/login'.format(CONSOLE),
                             data=json.dumps({'email':USERNAME, 'password':PASSWORD}),
                             headers={'Content-Type': 'application/json'}, verify=False)
    if response.status_code == 200:
        token = response.json()['access_token']
        return token
    else:
        print(response.text)
        return None

token = auth()

def bulk(events):

    
    
    if token:
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer '+token
        }

        response = requests.post('{}/api/v2.0/event/_bulk'.format(CONSOLE),
                                 data=json.dumps({"events": events}),
                                 headers=headers, verify=False)
        if response.status_code == 200:
            print(response.json())
        else:
            print(response.json())
    else:
        return events
    
def reference():
    return str(uuid.uuid4())

def case_templates():
  
  templates = [
    {"title":"Phishing Analysis","description":"Use this case template when investigating a Phishing e-mail.","tasks":[{"title":"Fetch original e-mail","description":"Get a copy of the original e-mail so that analysis can be performed on it to determine if it really is a phishing e-mail or not.","group_uuid":None,"owner_uuid":None,"order":"0"},{"title":"Notify users","description":"Send a phishing alert e-mail to all users so they are aware they may have been targeted.  This should buy time until the e-mail is scrubbed from the environment.","group_uuid":None,"owner_uuid":None,"order":"1"},{"title":"Quarantine","description":"Remove the original message from the e-mail environment","group_uuid":None,"owner_uuid":None,"order":"2"},{"title":"Post Mortem","description":"What have we learned from this event that could help in future events?","group_uuid":None,"owner_uuid":None,"order":"3"}],"tlp":2,"severity":2,"tags":["phishing"]}
  ]

def random_title_description():
  titles = [
    {'New Process Name in the last 30 days': 'A test event used for rule testing'},
    #{'User added to local administrators': 'Someone added a normal user to local admins'},
    #{'Suspicious DNS hit': 'A machine made a request for a suspicious DNS record'},
    #{'Local account discovery': 'A machine exhibited enumeration behavior'},
    #{'CVE-2021-40444': 'Remote code execution via malicious document in word'}
  ]

  return titles[random.randint(0, len(titles)-1)]

def random_severity():
  return random.randint(1,4)

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
    'butters',
    'svc_justin',
    'bro',
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
    'system',
    'brian'
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

def random_ip():
  return socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))

def random_powershell_command():
  commands = [

    'cmd.exe" /C powershell -NonInteractive -EncodedCommand cABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAALQBPAHUAdABwAHUAdABGAG8AcgBtAGEAdAAgAHQAZQB4AHQAIAAtAE4AbwBuAEkAbgB0AGUAcgBhAGMAdABpAHYAZQAgAC0AQwBvAG0AbQBhAG4AZAAgACcAJgAgAHsARwBlAHQALQBMAG8AYwBhAGwARwByAG8AdQBwAE0AZQBtAGIAZQByACAALQBHAHIAbwB1AHAAIAAnACcAQQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBzACcAJwAgAHwAIABzAGUAbABlAGMAdAAgAE4AYQBtAGUAfQAnACAAPgAgACIAQwA6AFwAVQBzAGUAcgBzAFwATgBCAEEAUwBDAFUAfgAxAFwAQQBwAHAARABhAHQAYQBcAEwAbwBjAGEAbABcAFQAZQBtAHAAXABwAG8AdwBlAHIAYwBsAGkAdgBtAHcAYQByAGUAMQA3ADcAIgA7ACAAZQB4AGkAdAAgACQAbABhAHMAdABlAHgAaQB0AGMAbwBkAGUA'
  ]

  return commands[random.randint(0, len(commands)-1)]

def random_event():
  alert_title = random_title_description()
  username = random_username()
  hostname = random_host_name()
  signature_values = [alert_title, username, hostname]
  event_hasher = hashlib.md5()
  event_hasher.update(str(signature_values).encode())
  ip = random_ip()
  
  alerts = [
    {
      "title": list(alert_title.keys())[0],
      "description": alert_title[list(alert_title.keys())[0]],
      "reference": reference(),
      "tags": [
        "enumeration",
        "T1262",
        "awesome: None"
      ],
      "tlp": 2,
      "source": "load_test.py",
      "signature": event_hasher.hexdigest(),
      "severity": random_severity(),
      "observables": [
        {
          "value": "ha-l-carroll",
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "data_type": "host",
          "source_field": "agent.hostname",
          "original_source_field": "agent.hostname",
          "tags": [
            "source-host", "windows", "internal"
          ]
        },
        {
          "value": "69293121724f2096e5afd92aa822f95a2407b19f2cc57a426eec24f291e37362",
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "data_type": "sha256hash",
          "source_field": "hash.sha256",
          "original_source_field": "hash.sha256",
          "tags": [
            "hash"
          ]
        },
        {
          "value": username,
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "data_type": "user",
          "source_field": "winlog.event_data.User",
          "original_source_field": "winlog.event_data.User",
          "tags": [
            "source-user", "corporate-user"
          ]
        },
        {
          "value": "S-1-5-21-1004336348-1177238915-682023330-512",
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "data_type": "sid",
          "source_field": "winlog.event_data.SubjectUserSid",
          "original_source_field": "winlog.event_data.SubjectUserSid",
          "tags": [
            "source-user", "corporate-user"
          ]
        },
        {
          "value": "svchost.exe",
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "data_type": "process",
          "source_field": "winlog.event_data.ImageName",
          "tags": [
            "source-user", "source-process"
          ]
        },
        {
          "value": random_powershell_command(),
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "data_type": "command",
          "source_field": "winlog.event_data.CommandLine",
          "tags": [
            "command"
          ]
        },
        
        {
          "value": "101.254.99.130",
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "data_type": "ip",
          "source_field": "source_ip",
          "tags": [
            "firewall",
            "source-ip"
          ]
        },
        {
          "value": ip,
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "data_type": "ip",
          "source_field": "source_ip",
          "tags": [
            "firewall",
            "source-ip"
          ]
        },
        {
          "value": random_ip(),
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "data_type": "ip",
          "source_field": "source_ip",
          "tags": [
            "firewall",
            "destination-ip"
          ]
        },
        {
          "value": random_ip(),
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "data_type": "auto",
          "source_field": "source_ip",
          "tags": [ 
            "firewall",
            "source"
          ]
        },
        {
          "value": "52.180.181.61",
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "data_type": "ip",
          "source_field": "source_ip",
          "tags": [
            "firewall"
          ]
        },
        {
          "value": 59852,
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "data_type": "port",
          "source_field": "destination_port",
          "tags": [
            "destination_port"
          ]
        }
      ],
      #"raw_log": json.dumps({"destination":{"ip": ip}})
      "raw_log": json.dumps({'match_body': {'event_data': {'TargetUserName': 'svc_justin'}}, 'host': {'name': 'HA-D-Awalt'}, 'user': {'name': 'josh', 'domain': 'TELLARO', 'target': {'name': 'justin', 'domain': 'TELLARO'}}})
    }
  ]

  return alerts[random.randint(0, len(alerts)-1)]



events = []
for i in range(0,EVENT_COUNT):
  headers = {
    'Content-Type': 'application/json'
  }
  event = random_event()
  
  events.append(event)
                                
  #if i % 2 == 0 :
  #  event['reference'] = reference()
  #  events.append(event)

# Split the events into 250 event chunks and send them
# in parallel using a thread pool
chunks = [events[x:x+250] for x in range(0, len(events), 250)]

with ThreadPoolExecutor(max_workers=10) as executor:
  executor.map(bulk, chunks)