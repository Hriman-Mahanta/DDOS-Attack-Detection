import dpkt
import socket
import pygeoip
import matplotlib.pyplot as plt
from collections import OrderedDict

def addlabels(x,y):
    for i in range(len(x)):
        plt.text(i, y[i], y[i], ha = 'center')

gi = pygeoip.GeoIP('GeoLiteCity.dat')

f = open('packets10.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)
country_list = []
for (ts, buf) in pcap:
    try:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        dst = socket.inet_ntoa(ip.dst)
        country_list.append(gi.country_name_by_addr(dst))
    except:
        pass
    
frequency = {}

for item in country_list:
    if item in frequency:
        frequency[item] += 1
    else:
        frequency[item] = 1

del frequency['Asia/Pacific Region']
frequency = OrderedDict(sorted(frequency.items(), key=lambda t: t[1], reverse=True))
print(frequency)
new_frequency = dict(list(frequency.items())[0:10]) 
plt.bar([ str(i) for i in new_frequency.keys()], new_frequency.values(), color='skyblue')
addlabels(list(new_frequency.keys()), list(new_frequency.values()))
plt.show()
