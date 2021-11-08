from rql import get_nested_field

data = {
    'observables': [
        {'name': 'Brian', 'data_type': 'user', 'tags':['source-user']},
        {'name': 'Administrator', 'data_type': 'user', 'tags':['destination-user']}
    ]}

data2 = {
    'observables': [
        {'name': 'Brian', 'data_type': 'user', 'tags':[{'name':'source-user'}]},
        {'name': 'Administrator', 'data_type': 'user', 'tags':[{'name':'destination-user'}]}
    ]}

print(get_nested_field(data, 'observables.tags'))
print(get_nested_field(data2,'observables.tags'))
print(get_nested_field(data2,'observables'))