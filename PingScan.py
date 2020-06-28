import os
import platform
from datetime import datetime

def scanner(net):
	ping1 = "ping -c 1 "
	t1 = datetime.now()
	comm = ping1 + net
	response = os.popen(comm)
	for line in response.readlines():
			if line.lower().count("ttl"):
				return True
	return False