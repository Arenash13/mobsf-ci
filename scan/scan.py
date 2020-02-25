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

def upload_apk():

    multipart_apk = MultipartEncoder(fields={'file' : (TARGET_APK, open(TARGET_APK, 'rb'), 'application/octet-stream')})
    headers = {'Authorization' : MOBSF_API_KEY, 'Content-Type' : multipart_apk.content_type}
    response = requests.post(url = '{}api/v1/upload'.format(MOBSF_URL), 
    headers = headers, 
    data=multipart_apk)
    response.raise_for_status()
    return response

def scan_apk(scan_type, file_name, hash , rescan):

    response = requests.post(url = '{}api/v1/scan'.format(MOBSF_URL), 
    headers={'Authorization' : MOBSF_API_KEY},
    data= {
        'scan_type' : scan_type,
        'file_name' : file_name,
        'hash' : hash,
        're_scan' : rescan
    })
    response.raise_for_status()
    return response
     
def retrieve_code(hash, file_name, file_type):

    response = requests.get(url=  '{}generate_downloads/?hash={}&file_type={}'.format(MOBSF_URL, hash, file_type))
    response.raise_for_status()
    with open("output/{}-{}.zip".format(file_name, file_type), 'wb') as zip:
        zip.write(response._content)

if __name__ == '__main__':

    logging.basicConfig(format='[%(levelname)s]: %(message)s', level=logging.INFO)

    logging.info('Uploading apk...')
    json_response = upload_apk().json()

    logging.info('Starting static analysis...')
    json_response = scan_apk(json_response['scan_type'], json_response['file_name'], json_response['hash'], RESCAN).json()
    logging.info("MobSF analysis finished")

    logging.info('Saving report...')
    with open('output/report.json', 'w') as report:
        report.write(json.dumps(json_response))
    logging.info('report generated at output/report.json')
    
    logging.info("Retrieving Java code...")
    retrieve_code(json_response["md5"], json_response["app_name"], 'java')
    logging.info("Done")

    logging.info("Retrieving Smali code...")
    retrieve_code(json_response["md5"], json_response["app_name"], 'smali')
    logging.info("Done")

    
    