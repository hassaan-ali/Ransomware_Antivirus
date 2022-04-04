# Ransomware_Antivirus
Using VirusTotal APIs

Two Files:
1. scan_id.py: To get scan_ids of all the given files in the dataset. The scan_id of each ransomware app are are stored in separate text files. These scan_ids are used in using virustotal api for ransomware analysis
2. report2.py: Takes the scan_ids generated using scan_id.py and outputs the .json and results file which includes the final output and result statitcs respectively. 
