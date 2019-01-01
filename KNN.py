
import ipaddress as IP
from sklearn.neighbors import NearestNeighbors

def CheckIP(address):
	samples = [[int(IP.ip_address(u'192.168.56.120'))],[int(IP.ip_address(u'192.168.56.200'))],[int(IP.ip_address(u'192.168.56.250'))], [int(IP.ip_address(u'10.0.0.20'))],[int(IP.ip_address(u'10.0.0.30'))], [int(IP.ip_address(u'10.0.0.100'))],[int(IP.ip_address(u'179.168.56.100'))]]


	neigh = NearestNeighbors(n_neighbors=1)
	neigh.fit(samples)


	malicious=(neigh.kneighbors([[int(IP.ip_address(address))]]))
	#print(neigh.kneighbors([[int(IP.ip_address(address))]]))


	#print(malicious[0][0][0])
	testdist=malicious[0][0][0]
	threshold=30


	if(testdist<=threshold):
		#print("Malicious IP detected")
		return -1
	if(testdist==0):
		return 2
        return 1

print(CheckIP(u'10.2.0.150'))

f=open("malware.txt","r")
add=f.readline()
add=add.rstrip()
print(CheckIP(unicode(add)))


