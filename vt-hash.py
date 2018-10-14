"""
Utilizing VirusTotal's API to send a hash and receive back results from different AV engine

Usage:
$ md5sum file.exe
$ python vt-hash.py [hash_here]

VT Results:
[AV Engine] -> [Malware Name]


"""

import urllib
import urllib2
import json
import sys

hash_vals = sys.argv[1]
vt_url = "https://virustotal.com/vtapi/v2/file/report"
api_key = "API_KEY"

params = {'apikey': api_key, 'resource': hash_vals}
encoded_params = urllib.urlencode(params)

request = urllib2.Request(vt_url, encoded_params)
response = urllib2.urlopen(request)

# mapping out the json response
json_res = json.loads(response.read())
if json_res['response_code'] :
 detection = json_res['positives']
 total = json_res['total']
 scan_results = json_res['scans']

print "Detection: %s/%s" % (detections, total)
print "VT Results:"
for av_name, av_data in scan_results.items():
 print "\t%s => %s" % (av_name, av_data['result'])
else:
 print "No current AV Detection for: %s" % hash_value
  
