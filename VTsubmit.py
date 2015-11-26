import requests, os, time, hashlib

file_dir = 'C:\Sysadmin_tools'
params = {'apikey': '23c479aa8d758b623162984a38894ed305591648440b7439d0632dce1a2e96b5'}

def md5sum(filename):
    hash = hashlib.md5()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash.update(chunk)
    return hash.hexdigest()

for root, directories, files in os.walk(file_dir):
    for filename in files:
        md5 = md5sum(os.path.join(root, filename))
        params = {'apikey': '23c479aa8d758b623162984a38894ed305591648440b7439d0632dce1a2e96b5', 'resource': md5}
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
                print('File:', filename)
                print('Positives:', json_response['positives'])
                print(json_response['scans']['Symantec'])
                print(json_response['scans']['TrendMicro'])
                print(json_response['scans']['Fortinet'])
                print(json_response['scans']['Kaspersky'])
                print(json_response['scans']['ClamAV'])
                print(json_response['scans']['McAfee'])
                print(json_response['scans']['DrWeb'])
                print(json_response['scans']['Sophos'])
                print(json_response['scans']['Avast'])
                print(json_response['scans']['Microsoft'])
                print(json_response['scans']['BitDefender'])
                print(json_response['scans']['Malwarebytes'])
                print(json_response['scans']['Avira'])
                print(json_response['scans']['ESET-NOD32'])
                print(json_response['scans']['F-Secure'])
                print(json_response['scans']['Panda'])
            else:
                print(filename, 'no malicious code found')
