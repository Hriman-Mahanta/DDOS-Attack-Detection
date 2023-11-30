import ipaddress
import multiprocessing

class datasetSummary:
    tcp_count = 0
    udp_count = 0
    igmp_count = 0
    not_analyzed_count = 0
    tcp = {}
    udp = {}

class pair_stats_tcp:
    src = 0
    dst = 0
    count = 0

class pair_stats_udp:
    src = 0
    dst = 0
    count = 0


class PacketAnalyse(multiprocessing.Process):
    def __init__(self, inQ, outQ):
        multiprocessing.Process.__init__(self)
        self.inQ = inQ
        self.outQ = outQ
        self.dvar = datasetSummary()

    def run(self):
        while True:
            if not self.inQ.empty():
                thePacket = self.inQ.get()
                if not thePacket:
                    self.outQ.put([])
                    break
                if not self.find_tcp(thePacket, self.dvar):
                    if not self.find_udp(thePacket, self.dvar):
                            if not self.find_igmp(thePacket, self.dvar):
                                self.dvar.not_analyzed_count += 1
                                
    def gen_src_dst_key(self, src, dst):
        if src < dst:
            return str(ipaddress.ip_address(src)) + "-" + str(ipaddress.ip_address(dst))
        else:
            return str(ipaddress.ip_address(dst)) + "-" + str(ipaddress.ip_address(src))

    def gen_ipv6_src_dst_key(self, src, dst):
        if src < dst:
            return (str(ipaddress.IPv6Address(src)) + "-" + str(ipaddress.IPv6Address(dst)))
        else:
            return (str(ipaddress.IPv6Address(dst)) + "-" + str(ipaddress.IPv6Address(src)))

    def gen_tcp_stats(self, existing_stats, packet_dict, srcKey, dstKey):
        pack_count = 0
        if existing_stats:
            pack_count = existing_stats.count
            pack_count += 1

        result = pair_stats_tcp()
        result.src = packet_dict[srcKey]
        result.dst = packet_dict[dstKey]
        result.count = pack_count

        return result

    def gen_udp_stats(self, existing_stats, packet_dict, srcKey, dstKey):
        pack_count = 0
        if existing_stats:
            pack_count = existing_stats.count
            pack_count += 1

        result = pair_stats_udp()
        result.src = packet_dict[srcKey]
        result.dst = packet_dict[dstKey]
        result.count = pack_count

        return result


    def find_tcp(self, packet_dict, dvar):
        success = False
        if "ip.proto" in packet_dict and (packet_dict["ip.proto"] != "6"):
            return success

        try:
            if ("tcp.srcport" in packet_dict and self.gen_src_dst_key(packet_dict["ip.src"], packet_dict["ip.dst"]) in dvar.tcp.keys()):
                packet_key = self.gen_src_dst_key(packet_dict["ip.src"], packet_dict["ip.dst"])
                status = dvar.tcp[packet_key]
                dvar.tcp[packet_key] = self.gen_tcp_stats(status, packet_dict, "ip.src", "ip.dst")
                dvar.tcp_count += 1
                self.send(packet_key, packet_dict, "tcp")
                success = True
            
            elif ("ip.src" in packet_dict and "tcp.flags.syn" in packet_dict):
                packet_key = self.gen_src_dst_key(packet_dict["ip.src"], packet_dict["ip.dst"])
                dvar.tcp[packet_key] = self.gen_tcp_stats({}, packet_dict, "ip.src", "ip.dst")
                dvar.tcp_count += 1
                self.send(packet_key, packet_dict, "tcp")
                success = True
            
            else:
                success = False
        
        except KeyError:
            if ("tcp.srcport" in packet_dict and self.gen_ipv6_src_dst_key(packet_dict["ipv6.src"], packet_dict["ipv6.dst"]) in dvar.tcp.keys()):
                packet_key = self.gen_ipv6_src_dst_key(packet_dict["ipv6.src"], packet_dict["ipv6.dst"])
                status = dvar.tcp[packet_key]
                dvar.tcp[packet_key] = self.gen_tcp_stats(status, packet_dict, "ipv6.src", "ipv6.dst")
                dvar.tcp_count += 1
                self.send(packet_key, packet_dict, "tcp")
                success = True
            
            elif ("ipv6.src" in packet_dict and "tcp.flags.syn" in packet_dict):
                packet_key = self.gen_ipv6_src_dst_key(packet_dict["ipv6.src"], packet_dict["ipv6.dst"])
                dvar.tcp[packet_key] = self.gen_tcp_stats({}, packet_dict, "ipv6.src", "ipv6.dst")
                dvar.tcp_count += 1
                self.send(packet_key, packet_dict, "tcp")
                success = True
            
            else:
                success = False

        except AttributeError:
            pass
        return success

    def find_udp(self, packet_dict, dvar):
        success = False
        if ("ip.proto" in packet_dict and (packet_dict["ip.proto"] != "17")):
            return success

        try:

            if ("udp.srcport" in packet_dict and self.gen_src_dst_key(packet_dict["ip.src"], packet_dict["ip.dst"]) in dvar.udp.keys()):
                packet_key = self.gen_src_dst_key(packet_dict["ip.src"], packet_dict["ip.dst"])
                status = dvar.udp[packet_key]
                dvar.udp[packet_key] = self.gen_udp_stats(status, packet_dict, "ip.src", "ip.dst")
                dvar.udp_count += 1
                self.send(packet_key, packet_dict, "udp")
                success = True

            elif "udp.srcport" in packet_dict:
                packet_key = self.gen_src_dst_key(packet_dict["ip.src"], packet_dict["ip.dst"])
                dvar.udp[packet_key] = self.gen_udp_stats({}, packet_dict, "ip.src", "ip.dst")
                dvar.udp_count += 1
                self.send(packet_key, packet_dict, "udp")
                success = True

            else:
                success = False

        except KeyError:

            if ("udp.srcport" in packet_dict and self.gen_ipv6_src_dst_key(packet_dict["ipv6.src"], packet_dict["ipv6.dst"]) in dvar.udp.keys()):
                packet_key = self.gen_ipv6_src_dst_key(packet_dict["ipv6.src"], packet_dict["ipv6.dst"])
                status = dvar.udp[packet_key]
                dvar.udp[packet_key] = self.gen_udp_stats(status, packet_dict, "ipv6.src", "ipv6.dst")
                dvar.udp_count += 1
                self.send(packet_key, packet_dict, "udp")
                success = True

            elif "udp.srcport" in packet_dict:
                packet_key = self.gen_ipv6_src_dst_key(packet_dict["ipv6.src"], packet_dict["ipv6.dst"])
                dvar.udp[packet_key] = self.gen_udp_stats({}, packet_dict, "ipv6.src", "ipv6.dst")
                dvar.udp_count += 1
                self.send(packet_key, packet_dict, "udp")
                success = True
            
            else:
                success = False
        return success


    def find_igmp(self, packet_dict, dvar):
        success = False
        if ("ip.proto" in packet_dict and (packet_dict["ip.proto"] != "2")):
            return success

        try:
            if "ip.src" in packet_dict and "ip.dst" in packet_dict:
                packet_key = self.gen_src_dst_key(packet_dict["ip.src"], packet_dict["ip.dst"])
                dvar.igmp_count += 1
                self.send(packet_key, packet_dict, "igmp")
                success = True
            elif "ipv6.src" in packet_dict and "ipv6.dst" in packet_dict:
                packet_key = self.gen_ipv6_src_dst_key(packet_dict["ipv6.src"], packet_dict["ipv6.dst"])
                dvar.igmp_count += 1
                self.send(packet_key, packet_dict, "igmp")
                success = True
        except AttributeError:
            success = False
        return success

    def send(self, ID, PacketData, PacketProtocol):
        self.outQ.put(
            {
                "Id": ID,
                "Packet": PacketData,
                "Protocol": PacketProtocol
            }
        )
