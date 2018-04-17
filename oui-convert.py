import re
import json
import requests

def main():
    response = dict()

    r = requests.get('https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf', verify=False)
    lines = r.text.splitlines()

    for line in lines:
        line = line.encode('utf-8', 'ignore')

        if line.startswith(b'#'):
            continue
        splitted = line.split(b'\t')
        mac_prefix = splitted[0]
        mac_prefix = mac_prefix.strip()
        is_valid_mac_prefix = re.match(r'^([0-9|A-F|a-f]{2}[:|-]){2}([0-9|A-F|a-f]{2})$', mac_prefix.decode('utf-8'))
        is_valid_mac_mask = re.match(r'^([0-9|A-F|a-f]{2}[:|-]){5}(00\/36)$', mac_prefix.decode('utf-8'))
        if not is_valid_mac_prefix:
            if is_valid_mac_mask:
                mac_prefix = mac_prefix.replace(b':00/36', b'')
            else:
                continue

        splitted = splitted[1].split(b'#')
        name = splitted[0]
        name = name.strip()

        description = name
        if len(splitted) > 1 :
            description = splitted[1]
            description = description.strip()

        if not name:
            continue

        response[mac_prefix.decode('utf8')] = {'name': name.decode('utf8'), 'description': description.decode('utf8')}
    return response

if __name__ == '__main__':
    data = main()
    json_string = json.dumps(data)

    with open('json_data.json','w') as f:
        f.write(json_string)
