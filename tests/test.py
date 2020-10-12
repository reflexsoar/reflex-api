import datetime

observables = []

data = {
    'BRIAN-PC': [
        {'created_at': datetime.datetime(2020, 9, 13, 1, 40, 40, 63700), 'uuid': '574ea340-4157-415e-aa2e-f8ed0ddd5cdd'}, 
        {'created_at': datetime.datetime(2020, 9, 13, 1, 40, 40, 224703), 'uuid': '111431b8-a5f6-404e-a78a-8513c6d0aadd'}
    ], 
    'Brian': [
        {'created_at': datetime.datetime(2020, 9, 13, 1, 40, 40, 96705), 'uuid': 'ea02e0b9-72a6-4bb4-bc8e-8f3d59f08309'}, 
        {'created_at': datetime.datetime(2020, 9, 13, 1, 40, 40, 254704), 'uuid': '4ab59143-4e2c-47de-b53c-b14067dec375'}
    ],
    'whoami': [
        {'created_at': datetime.datetime(2020, 9, 13, 1, 40, 40, 128703), 'uuid': '5a5fb659-bf97-44aa-a9de-5d861f74613c'}
    ],
    'whoami /priv': [
        {'created_at': datetime.datetime(2020, 9, 13, 1, 40, 40, 285700), 'uuid': '0e281a18-dd42-40ee-a9a4-2bf2d3d7a5d7'}]
    }

print(data)
for observable in data:
    data[observable] = sorted(data[observable], key=lambda x: x['created_at'], reverse=True)
    observables.append(data[observable][0])

print(data)
for observable in observables:
    print(observable['uuid'], datetime.datetime.timestamp(observable['created_at']))