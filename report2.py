import os
import os.path
import virustotal3
import requests
import json
from pathlib import Path
sha256 = []
dictionary = {}
totalfiles = 0
benign_files = 0
# Location where output will be written
path_to_file = "test3.json"
path = Path(path_to_file)
url = 'https://www.virustotal.com/vtapi/v2/file/report'
filenames = ["SimpleLocker.txt",  "Roop.txt", "Koler.txt", "Jisut.txt", "Fusob.txt", "Aples.txt"]
for files in filenames:
    with open(files, "r") as file1:
        for i in file1.readlines():
            totalfiles+=1
            params = {'apikey': '9b123d4c8003f5071e7c84bc76e93772d5191d33ca0ea8f2cf4867421b74b23f', 'resource': i}
            response = requests.get(url, params=params)
            sha256.append(response.json()["sha256"])
            '''
            if response.json()["sha256"] in sha256:
                header = "ransom" + '_' + (os.path.splitext(files)[0]) + '_' + response.json()["sha256"]
                json_data = response.json()["scans"]
                accuracy = response.json()["positives"] / response.json()["total"]
                if response.json()["positives"] == 0:
                    accuracy = 100
                    #header = "benign" + '_' + response.json()["sha256"]
                dictionary[header].update({
                        "oat": {
                            "detected_count": response.json()["positives"],
                            "total_av": response.json()["total"],
                            "accuracy": accuracy
                        }
                    }
                )

                # appending av_names and detected values in the dictionary
                for x in json_data:
                    dictionary[header]["oat"].update({x: json_data[x]["detected"]})
                continue '''



            header = "ransom" + '_' + (os.path.splitext(files)[0]) + '_' + response.json()["sha256"]
            json_data = response.json()["scans"]
            accuracy = response.json()["positives"] / response.json()["total"]
            if response.json()["positives"] == 0:
                accuracy = 100
                #header = "benign" + '_' + response.json()["sha256"]
                benign_files+=1
            dictionary.update({
                header : {
                    "apk": {
                        "detected_count": response.json()["positives"],
                        "total_av": response.json()["total"],
                        "accuracy": accuracy
                    }
                }
            })

            #appending av_names and detected values in the dictionary
            for x in json_data:
                dictionary[header]["apk"].update({x:json_data[x]["detected"]})

# Serializing json
json_object = json.dumps(dictionary, indent=4)

with open(path_to_file, "w") as outfile:
    outfile.write(json_object)
    outfile.write('\n')

print("Total Files Scaned: ", totalfiles)
print("Benign Files: ", benign_files)
print("Infected Files: ", totalfiles-benign_files)
