import time, urllib.request, urllib.parse, json

log_file = "C:\\Users\\304452\\Desktop\\phising_patterns2.txt"
with open(log_file) as f:
    urls = f.readlines()

def urlreport(url):
    vturl = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'resource': url, 'apikey': '23c479aa8d758b623162984a38894ed305591648440b7439d0632dce1a2e96b5'}
    data = urllib.parse.urlencode(params).encode('utf8')
    response = urllib.request.urlopen(vturl, data)
    data = json.loads(response.read().decode('utf8'))
    return(data)