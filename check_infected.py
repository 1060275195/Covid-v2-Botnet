import socket

def check_infected(ip):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((ip, 6969))
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
