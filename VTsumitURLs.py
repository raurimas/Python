import requests, time

log_file = 'C:\Users\304452\Desktop\phising_patterns2.txt'
with open(log_file) as f:
    urls = f.readlines()

for url in urls:
    print(url)
    params = {'url': url, 'apikey': '23c479aa8d758b623162984a38894ed305591648440b7439d0632dce1a2e96b5'}
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/scan', params=params)
    json_response = response.json()
    print(json_response)

    # Public API allows to scan 4 files per minute
    time.sleep(15)