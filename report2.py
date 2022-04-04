import os
import os.path
import virustotal3
import requests
import json
from pathlib import Path
dictionary = {} #output which will converted to json
# Location where output will be written
path_to_file = "output.json" #Final json file
path = Path(path_to_file)
url = 'https://www.virustotal.com/vtapi/v2/file/report' #virustotal API
filenames = ["SimpleLocker.txt",  "Roop.txt", "Koler.txt", "Jisut.txt", "Fusob.txt", "Aples.txt", "Aples-oat.txt", "Benign-oat.txt", "Benign.txt"] #files with scan_ids
def get_json():
    totalfiles = 0 #number of files scanned
    benign_files = 0 #benign files
    false_negative = 0
    filetype = "" #apk,dex or oat
    ransom_type = "" #SimpleLocker, Fusob, etc.

    for files in filenames:
        if files == "Aples-oat.txt":
            ransom_type = "ransom" + '_' + "Aples" + '_'
        elif files == "Benign-oat.txt" or files == "Benign.txt":
            ransom_type = "benign" + '_'
        else:
            ransom_type = "ransom" + '_' + (os.path.splitext(files)[0]) + '_'
        with open(files, "r") as file1:
            for i in file1.readlines():
                totalfiles+=1
                params = {'apikey': '9b123d4c8003f5071e7c84bc76e93772d5191d33ca0ea8f2cf4867421b74b23f', 'resource': i}
                response = requests.get(url, params=params)

                header = ransom_type + response.json()["sha256"] #using hash sha256
                json_data = response.json()["scans"]
                accuracy = response.json()["positives"] / response.json()["total"]
                if response.json()["positives"] == 0 and (files == "Benign-oat.txt" or files == "Benign.txt"):
                    accuracy = 100
                    benign_files+=1
                elif response.json()["positives"] == 0 and (files != "Benign-oat.txt" or files != "Benign.txt"):
                    accuracy = "False Negative"
                    false_negative+=1
                if files == "Aples-oat.txt" or files == "Benign-oat.txt":
                    filetype = "oat"
                elif files == "Benign.txt":
                    filetype = "dex"
                else:
                    filetype = "apk"
                dictionary.update({
                    header : {
                        filetype: {
                            "detected_count": response.json()["positives"],
                            "total_av": response.json()["total"],
                            "accuracy": accuracy
                        }
                    }
                })

                #appending av_names and detected values in the dictionary
                for x in json_data:
                    dictionary[header][filetype].update({x:json_data[x]["detected"]})



    # Serializing json
    json_object = json.dumps(dictionary, indent=4)

    with open(path_to_file, "w") as outfile:
        outfile.write(json_object)
        outfile.write('\n')

    with open("results.txt", "w") as results:
        results.write("Total files scanned: " + str(totalfiles))
        results.write('\n')
        results.write("Infected Files: " + str(totalfiles-benign_files))
        results.write('\n')
        results.write("Benign Files: " + str(benign_files))
        results.write('\n')
        results.write("False Negatives: " + str(false_negative))
        results.write('\n')
        results.write("Infected Files %: " + str(((totalfiles-benign_files)/totalfiles)*100))

if __name__ == "__main__":
    get_json()