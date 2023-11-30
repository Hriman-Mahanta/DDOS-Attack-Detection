import multiprocessing

class ServiceIdentity(multiprocessing.Process):
    def __init__(self, inQ, outQ):
        multiprocessing.Process.__init__(self)
        self.inQ = inQ
        self.outQ = outQ

    def run(self):
        service_count = 0
        while True:
            if not self.inQ.empty():
                Datalist = self.inQ.get()
                if not Datalist:
                    self.outQ.put({})
                    break
                service_count += 1
                ID = Datalist["Id"]
                packet_dict = Datalist["Packet"]
                packet_protocol = Datalist["Protocol"]
                found_services = self.findServices(ID, packet_dict, packet_protocol)
                if found_services:
                    Datalist["Services"] = found_services
                else:
                    Datalist["Services"] = {"no service"}
                self.outQ.put(Datalist)

    def findServices(self, ID, packet_dict, packet_protocol):
        found_services = set()
        if packet_protocol == "tcp" or packet_protocol == "udp":
            self.tls(packet_dict, found_services)
            self.http(packet_dict, found_services)
            self.dns(packet_dict, found_services)
            self.dhcp(packet_dict, found_services)
            if not found_services:
                pass
        return found_services

    def tls(self, packet_dict, found_services):
        if "tls.record.content_type" in packet_dict:
            found_services.add("tls")

    def http(self, packet_dict, found_services):
        if "http.request.method" in packet_dict:
            found_services.add("http")

    def dns(self, packet_dict, found_services):
        if "dns.flags" in packet_dict:
            found_services.add("dns")

    def dhcp(self, packet_dict, found_services):
        if "dhcp.type" in packet_dict or "dhcpv6.msgtype" in packet_dict:
            found_services.add("dhcp")
