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
    def __init__(self, ips, ports, threads=20):
        self.ips = ips
        self.ports = ports
        self.threads = threads
        self.lock = threading.BoundedSemaphore(value=self.threads)
        self.tasks = []
        global ip_ports

    def run(self):
        for ip in self.ips:
            t = threading.Thread(target=self.port_scan, args=(ip, self.ports))
            self.tasks.append(t)
        for task in self.tasks:
            task.start()

        for task in self.tasks:
            task.join()

    def port_scan(self, host, ports):
        print '[start port scan %s]' % host
        ip_ports[host] = {"port": [], "http": []}
        self.lock.acquire()
        try:
            nm = nmap.PortScanner()
            nm.scan(host, ports)
            for ip in nm.all_hosts():
                tcp_info = nm[ip]['tcp']
                for port in tcp_info:
                    port_info = tcp_info[port]
                    state = port_info['state']
                    if state == 'open':
                        name = port_info['name']
                        product = port_info['product']
                        version = port_info['version']
                        port_banner = "%d:%s %s %s" % (port,name,product,version)
                        print ip,port_banner
                        ip_ports[ip]['port'].append(port_banner)

                        if name == 'http':
                            for domain in [host] + self.ips[host]:
                                try:
                                    url = "http://%s:%s/" % (domain,port)
                                    html = requests.get(url,timeout=10).content
                                    charset = chardet.detect(html)['encoding']
                                    try:
                                        title = re.findall(r'<title>(.*?)</title>', html, re.IGNORECASE)[0]
                                        if 'gb' in charset.lower():
                                            title = title.decode('gbk')
                                        else:
                                            title = title.decode('utf-8')
                                    except:
                                        title = "not found"
                                except:
                                    pass
                                w_banner = "%s:%d\t%s\t%s\t%s" % (domain,port,product,version,title)
                                ip_ports[ip]["http"].append(w_banner)


        except Exception, e:
            print '[port scan]', traceback.print_exc()
            pass
        if len(ip_ports[host]["http"]) == 0:
            for domain in [host] + self.ips[host]:
                ip_ports[host]["http"].append(domain + '\n')
        self.lock.release()
        print 'end of scan:', host, ip_ports[host]
			
			
def main():
	fname = sys.argv[1]#fname = 'huazhu.txt'
	thread = sys.argv[2]
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
	pscan = portscan(ip_domains, ports_set, thread)
	pscan.run()


	output = open(fname[:-4] + '_ports.txt', 'ab+')
	for ip in ip_ports:
		print ip, ip_ports[ip]
		output.write(ip + ':\n')
		output.write('\n'.join(ip_ports[ip]["port"]) + '\n')
		output.write('\n'.join(ip_ports[ip]["http"]) + '\n')
		output.write('========================================\n')

	output.close()


if __name__=="__main__":
	main()