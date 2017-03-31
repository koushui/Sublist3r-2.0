#!/usr/bin/env python
# coding: utf-8
# By 00theway
import dns.resolver
import threading,nmap,argparse,re,requests,traceback,chardet
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

global ip_ports,ip_domains
ip_ports = {}
ip_domains = {}




class resolvedomain():
	def __init__(self,domains,threads=20):
		self.domains = domains
		self.threads = threads
		self.lock = threading.BoundedSemaphore(value=self.threads)
		self.resolver = dns.resolver.Resolver()
		self.resolver.nameservers = ['114.114.114.114','233.5.5.5']
		self.tasks = []


	def isIP(self,str):
		p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
		if p.match(str):
			return True
		else:
			return False
	
	def lookup(self,domain):
		self.lock.acquire()
		try:
			ips = self.resolver.query(domain)
			addr = ''
			for ip in ips:
				addr = ip.address.strip()
				#print domain,addr
				if addr in ip_domains and domain not in ip_domains[addr]:
					ip_domains[addr].append(domain)
				else:
					ip_domains[addr] = [domain]
		except Exception,e:
			print '[lookup]',e
		self.lock.release()
		
	def run(self):
		for domain in self.domains:
			if self.isIP(domain):
				ip_domains[domain] = [domain]
			else:
				t = threading.Thread(target=self.lookup, args=(domain.strip(),))
				self.tasks.append(t)
		for task in self.tasks:
			task.start()
			
		for task in self.tasks:
			task.join()

			
class portscan():
	def __init__(self, ips, ports):
		self.ips = ips
		self.ports = ports
		self.threads = 20
		self.lock = threading.BoundedSemaphore(value=self.threads)
		self.tasks = []

	def port_scan(self, host, ports):
		print 'start scan %s' % host
		ip_ports[host] = {"port":[],"http":[]}
		self.lock.acquire()
		try:
			nm = nmap.PortScanner()
			nm.scan(host,ports)
			for port in nm[host]['tcp'].keys():
				if nm[host]['tcp'][port]['state'] == 'open':
					port_banner = '%d:%s %s\n' % (port,nm[host]['tcp'][port]['product'],nm[host]['tcp'][port]['version'])
					ip_ports[host]["port"].append(port_banner)
					title = 'not found'
					if nm[host]['tcp'][port]['name'] == 'http':
						for domain in [host] + self.ips[host]:
							try:
								html = requests.get("http://%s:%s" % (domain,port),timeout=10).content
								charset = chardet.detect(html)['encoding']
								try:
									title = re.findall(r'<title>(.*?)</title>', html ,re.IGNORECASE)[0]
									if 'gb' in charset.lower():
										title = title.decode('gbk')
									else:
										title = title.decode('utf-8')
								except:
									title = 'not found'
							except:
								pass
							banner = '%s\t%d:%s %s\t%s\n' % (domain,port,nm[host]['tcp'][port]['product'],nm[host]['tcp'][port]['version'],title)
							ip_ports[host]["http"].append(banner)
			if len(ip_ports[host]["http"]) == 0:
				for domain in [host] + self.ips[host]:
					ip_ports[host]["http"].append(domain + '\n')
								


		except Exception,e:
			print '[port scan]',traceback.print_exc()
			pass
		self.lock.release()
		print 'end of scan:',host,ip_ports[host]

	def run(self):
		for ip in self.ips:
			t = threading.Thread(target=self.port_scan, args=(ip, self.ports))
			self.tasks.append(t)
		for task in self.tasks:
			task.start()
			
		for task in self.tasks:
			task.join()
			
			
def main():
	fname = sys.argv[1]
	#fname = 'huazhu.txt'
	domains = open(fname).read().splitlines()

	
	rdomain = resolvedomain(domains)
	rdomain.run()

	ports = ['21','22','23'
	,'80-90'
	,'443','8443'
	,'8080','8000','8081','8089','8088','8090','8880','8888','9090','9875','9200','9300','9999'
	,'6379'#redis
	,'1433'#sqlserver
	,'3306'#mysql
	,'1521'#oracle
	,'4848'#glassfish
	,'7001'#weblogic
	,'8500'#coldfusion
	,'9060','9043','9080','9043'#websphere
	]
	ports_set = ','.join(ports)
	#ports_set = '1-1000,7000-10000'
	pscan = portscan(ip_domains, ports_set)
	pscan.run()

	for ip in ip_domains:
		print ip,ip_ports[ip],ip_domains[ip]
		open('%s-portsinfo.txt' % (fname[:-4]),'ab+').write(ip+':\n' + ''.join(ip_ports[ip]["port"]) + ''.join(ip_ports[ip]["http"]) +'\n========================================\n')

if __name__=="__main__":
	main()