import os
import os.path
import virustotal3
import requests


def get_files(mypath):
    all_files = []
    for dirpath, dirnames, filenames in os.walk(mypath):
        for filename in [f for f in filenames if f.endswith(".apk")]:
            all_files.append(os.path.join(dirpath, filename))

    return all_files

def get_scan_id(all_files, url, params):
    scan_ids = []
    for i in all_files:
        files = {'file': ('myfile.exe', open(i, 'rb'))}
        response = requests.post(url, files=files, params=params)
        scan_ids.append(response.json()['scan_id'])
    return scan_ids

if __name__ == "__main__":
    simpleLocker = []
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': '9b123d4c8003f5071e7c84bc76e93772d5191d33ca0ea8f2cf4867421b74b23f'}
    #SimpleLocker
    all_files = get_files('C:\\Users\\Hassaan\\OneDrive - Umich\\Documents\\CIS 549 Software Security\\Term Project\\small_apk_dataset\\Benign')
    file1 = open("Benign.txt", "w")
    file1.writelines('\n'.join(get_scan_id(all_files,url,params)) + '\n')
    file1.close()



