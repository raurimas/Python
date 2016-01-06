import urllib.request, urllib.parse
from xml.etree import ElementTree

log_file = "C:\\Users\\test\\log.txt"
with open(log_file) as f:
    urls = f.readlines()

def urlreport(url):
    urlvoid = 'http://api.urlvoid.com/api1000/6a80bc6bbb0e7920c00dff9cc909344f29038736/host/'
    response = urllib.request.urlopen(urlvoid + url.strip('\n') + '/scan/')
    data = response.read().decode('utf8')
    tree = ElementTree.fromstring(data)
    try:
        return tree.find('action_result').text
    except Exception:
        pass

for url in urls:
    urlstatus = urlreport(url)
    if urlstatus != None:
        print(url.strip('\n'), urlstatus)
    else:
        print(url.strip('\n'), 'Domain not valid or error occured')
