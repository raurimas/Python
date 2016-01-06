import requests, os, time, hashlib

file_dir = 'C:\Sysadmin_tools'

def sha256sum(filename):
    hash = hashlib.sha256()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash.update(chunk)
    return hash.hexdigest()

for root, directories, files in os.walk(file_dir):
    for filename in files:
        sha256hash = sha256sum(os.path.join(root, filename))
        params = {'apikey': '23c479aa8d758b623162984a38894ed305591648440b7439d0632dce1a2e96b5', 'resource': sha256hash}
        response = requests.get('http://www.virustotal.com/vtapi/v2/file/report', params=params)
        json_response = response.json()

        # Public API allows to scan 4 files per minute
        time.sleep(15)

        # If file not checked by VirusTotal yet, submit it for scanning
        if json_response['response_code'] == 0:
            # Public API allows files <= 32 MB
            if (round(os.path.getsize(os.path.join(root, filename))/1024/1024)) <= 32:
                params = {'apikey': '23c479aa8d758b623162984a38894ed305591648440b7439d0632dce1a2e96b5'}
                files = {'file': (os.path.join(filename), open(os.path.join(root, filename), 'rb'))}
                response = requests.post('http://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
                json_response = response.json()
                print(json_response['verbose_msg'])
        else:
            if json_response['positives'] > 0:
                print(filename, 'scan date:', json_response['scan_date'], 'detected:', json_response['positives'], 'VT URL:', json_response['permalink'])
            else:
                print(filename, 'no malicious code found')
