import re
import base64

def mutate_extractb64(value):
    '''
    Extracts a base64 string or strings from a input string and decodes them
    so they can be compared down the pipeline
    '''
    try:
        decoded_matches = []
        if isinstance(value, str):
            pattern = re.compile(r'\s+([A-Za-z0-9+/]{20}\S+)')
            matched = pattern.findall(value)
            if len(matched) > 0:
                decoded_matches = [base64.b64decode(match).decode() for match in matched]
                return decoded_matches
        return value
    except:
        return value


print(mutate_extractb64("powershell -encodedCommand SW52b2tlLVdlYlJlcXVlc3QgaHR0cHM6Ly93d3cucmVmbGV4c29hci5jb20= -encodedCommand SW52b2tlLVdlYlJlcXVlc3QgaHR0cHM6Ly93d3cucmVmbGV4c29hci5jb20="))
print(mutate_extractb64("foobar"))
print(mutate_extractb64(1))
