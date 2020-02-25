import os 
import logging
import requests
import json
import subprocess
from requests_toolbelt.multipart.encoder import MultipartEncoder
from requests_toolbelt.utils import dump

# retrieve some variables from the yaml
MOBSF_URL = os.environ['MOBSF_URL']
TARGET_APK = os.environ['TARGET_PATH']
MOBSF_API_KEY = os.environ['MOBSF_API_KEY']
RESCAN = os.environ['RESCAN']

def check_http_response(response):
   
    if response.ok:
        return response
    # Will raise an HTTPError if an error has occured
    response.raise_for_status()

def upload_apk():

    multipart_apk = MultipartEncoder(fields={'file' : (TARGET_APK, open(TARGET_APK, 'rb'), 'application/octet-stream')})
    headers = {'Authorization' : MOBSF_API_KEY, 'Content-Type' : multipart_apk.content_type}
    response = requests.post(url = '{}api/v1/upload'.format(MOBSF_URL), 
    headers = headers, 
    data=multipart_apk)
    return check_http_response(response)

def scan_apk(scan_type, file_name, hash , rescan):

    response = requests.post(url = '{}api/v1/scan'.format(MOBSF_URL), 
    headers={'Authorization' : MOBSF_API_KEY},
    data= {
        'scan_type' : scan_type,
        'file_name' : file_name,
        'hash' : hash,
        're_scan' : rescan
    })
    return check_http_response(response)
     
def retreive_source_code(hash, file, type):

    response = requests.post(url='{}api/v1/view_source'.format(MOBSF_URL),
    headers={'Authorization' : MOBSF_API_KEY},
    data={'hash' : hash,
    'file' : file,
    'type' : type})
    return check_http_response(response)

if __name__ == '__main__':

    logging.basicConfig(format='\n[%(levelname)s]: %(message)s', level=logging.INFO)

    # logging.info('Uploading apk...')
    # json_response = upload_apk().json()

    # logging.info("Retreive source code...")
    # response = retreive_source_code(json_response['hash'], "owasp/mstg/uncrackable3/R.java", json_response['scan_type'])
    # print(response.json())

    
    #print(requests.get(url=  '{}Java/?md5={}&type={}'.format(MOBSF_URL, json_response['hash'], json_response['scan_type']))._content)
# 
    # logging.info('Start static analysis...')
    # json_response = scan_apk(json_response['scan_type'], json_response['file_name'], json_response['hash'], RESCAN).json()
# 
    # print(json_response["md5"])
# 
    json_response = {'md5' : 'b2019c64125edcaa577ff8d44f3244a5'}
    response = requests.get(url=  '{}generate_downloads/?hash=b2019c64125edcaa577ff8d44f3244a5&file_type=java'.format(MOBSF_URL))
    #response = requests.get(url=  '{}download/{}-java.zip'.format(MOBSF_URL, json_response["md5"]))
    
    response2 = requests.get(url=  '{}download/b2019c64125edcaa577ff8d44f3244a5-java.zip'.format(MOBSF_URL))
    #print(dump.dump_all(response2))
    with open ("output/test", 'wb') as f:
        f.write(response2._content)
    #print(response)
    #with open("output/")

    # logging.info('Saving report...')
    # with open('output/report.json', 'w') as report:
    #     report.write(json.dumps(json_response))
    # logging.info('report generated at output/report.json')
    
    