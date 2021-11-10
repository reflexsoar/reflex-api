from rql.base import RQLSearch

search = RQLSearch()

data = [{
    'observables': [{'value':'A', 'tlp': 1, 'malware': True}, {'value':'Brian2', 'tlp': 2, 'malware': 2}]
}]

print("DATA:", data)
print()

print('Observable.value = A AND observable.tlp = 1 and observable.malware: true')
result = filter(search.Each(search.And(search.Match(**{'value':'A'}),search.Match(**{'tlp':1}),search.Is(**{'malware':True})), key='observables'), data)
for r in result:
    print(r)

print()
print('Observable.value = A AND observable.tlp = 2 but A\'s TLP is 1 - BAD')
result = filter(search.And(search.Match(**{'observables.value':'A'}),search.Match(**{'observables.tlp':2})), data)
for r in result:
    print(r)
