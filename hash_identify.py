import subprocess
import time
import hashlib

def check_hash(hash):
	out = subprocess.check_output(['hashid', hash])
	out = out.decode('utf-8').strip('\r\n')
	lines = out.split('\n')
	resaults = []
	for i in range(len(lines) -1):
		word = lines[i+1].split(" ")[1].replace(" ","").replace("-","").lower()
		if word in hashlib.algorithms_available:
			resaults.append(word)
	return resaults