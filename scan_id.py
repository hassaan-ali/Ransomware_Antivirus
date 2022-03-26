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
    params = {'apikey': '<insert VirusTotal API key>'}
    #SimpleLocker
    all_files = get_files('<Insert directory path>')
    file1 = open("Benign.txt", "w")
    file1.writelines('\n'.join(get_scan_id(all_files,url,params)) + '\n')
    file1.close()



