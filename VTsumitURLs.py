import time, urllib.request, urllib.parse
#from urllib.parse import urlencode

log_file = "C:\\Users\\304452\\Desktop\\phising_patterns2.txt"
with open(log_file) as f:
    urls = f.readlines()

for url in urls:
    vturl = "https://www.virustotal.com/vtapi/v2/url/scan"
    params = {'url': url, 'apikey': '23c479aa8d758b623162984a38894ed305591648440b7439d0632dce1a2e96b5'}
    data = urllib.parse.urlencode(params).encode('utf8')
    response = urllib.request.urlopen(vturl, data)
    response_bytes = response.read()
    response = response_bytes.decode('utf8')
    print(response)

    # Public API allows to scan 4 files per minute
    time.sleep(15)