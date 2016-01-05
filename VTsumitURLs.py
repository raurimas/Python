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

for url in urls:
    # If file not checked by VirusTotal yet, submit it for scanning
    # URLs submitted by API get lowest scan priority
    report = urlreport(url)
    if (report['response_code']) == 0:
        vturl = 'https://www.virustotal.com/vtapi/v2/url/scan'
        params = {'resource': url, 'apikey': '23c479aa8d758b623162984a38894ed305591648440b7439d0632dce1a2e96b5'}
        data = urllib.parse.urlencode(params).encode('utf8')
        response = urllib.request.urlopen(vturl, data)
        # NETRINTI
        #time.sleep(60)
        #report = urlreport(url)


        while True:
            print(time.strftime("%Y-%m-%d %H:%M"))
            report = urlreport(url)
            print(report['verbose_msg'])
            time.sleep(60)
            if report['verbose_msg'] == 'Scan finished, scan information embedded in this object':
                print(report)
                break


        # NETRINTI
        #print('URL:', report['url'], 'Scan date:', report['scan_date'], 'Positives:', report['positives'] , 'VT:', report['permalink'])
    else:
        print('URL:', report['url'], 'Scan date:', report['scan_date'], 'Positives:', report['positives'] , 'VT:', report['permalink'])

        # Public API allows to scan 4 files/URLs per minute
        time.sleep(15)