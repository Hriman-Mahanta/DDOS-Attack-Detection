import multiprocessing
import csv
from datetime import datetime

class windowcounts:
    window_end_time = 0
    window_index = 1

    tcp_frame_length = 0
    tcp_ip_length = 0
    tcp_length = 0

    udp_frame_length = 0
    udp_ip_length = 0
    udp_length = 0

    num_tls = 0
    num_http = 0
    num_dns = 0
    num_dhcp = 0
    num_tcp = 0
    num_udp = 0
    num_igmp = 0

    IDs = set()
    ports = set()

    num_packets = 1

    def __init__(self, time_window_end=0, window_index=1):
        self.num_packets = 1
        self.IDs = set()
        self.ports = set()
        self.window_end_time = time_window_end
        self.window_index = window_index


class TimesAndCounts(multiprocessing.Process):
    fieldnames = [
        "tcp_frame_length",
        "tcp_ip_length",
        "tcp_length",
        "udp_frame_length",
        "udp_ip_length",
        "udp_length",
        "num_tls",
        "num_http",
        "num_dhcp",
        "num_dns",
        "num_tcp",
        "num_udp",
        "num_igmp",
        "num_connection_pairs",
        "num_ports",
        "num_packets",
        "window_end_time",
    ]

    def __init__(self, time_window, csv_file_path, inQ):
        multiprocessing.Process.__init__(self)
        self.time_window = time_window
        self.csv_file_path = csv_file_path
        self.inQ = inQ
        self.cvar = windowcounts()
        self.current_time = 0

    def run(self):
        with open(self.csv_file_path, "w") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames, restval="0")
            writer.writeheader()
            csvfile.flush()

            pack_count = 0
            time_window_index = 0
            time_window_stop = 0

            while True:
                if not self.inQ.empty():
                    pack_count += 1
                    Datalist = self.inQ.get()
                    if not Datalist:
                        break

                    ID = Datalist["Id"]
                    packet_dict = Datalist["Packet"]
                    Prot1 = Datalist["Protocol"]
                    services = Datalist["Services"]

                    if pack_count == 1:
                        (time_window_index, time_window_stop, self.current_time) = self.timecheck( packet_dict["frame.time_epoch"], 0, time_window_index)
                        self.cvar.window_end_time = time_window_stop

                    (time_window_index, time_window_stop, self.current_time) = self.timecheck(packet_dict["frame.time_epoch"], time_window_stop,time_window_index)

                    if time_window_index == self.cvar.window_index:
                        self.cvar.num_packets += 1
                    else:
                        self.write_window(writer, self.cvar)
                        csvfile.flush()
                        self.cvar = self.reset_window(time_window_stop, self.cvar.window_index)

                    self.calculate(ID, packet_dict, Prot1, services, self.cvar)
            print("Total number of packets", pack_count)
            csvfile.close()

    def timecheck(self, frame_time_epoch, time_window_stop, time_window_index):
        packet_frame_time = int(float(frame_time_epoch) * 1000)

        if packet_frame_time <= time_window_stop:
            pass
        else:
            time_window_index += 1
            if time_window_stop == 0:
                time_window_start_ceil = packet_frame_time
            else:
                time_window_start_ceil = time_window_stop
            time_window_stop = time_window_start_ceil + self.time_window

        return (time_window_index, time_window_stop, packet_frame_time)

    def calculate(self, ID, packet_dict, Prot1, services, cvar):
        if Prot1 == "tcp":
            cvar.tcp_frame_length = cvar.tcp_frame_length + int(packet_dict["frame.len"])
            try:
                cvar.tcp_ip_length = cvar.tcp_ip_length + int(packet_dict["ip.len"])
            except KeyError:  # does not exist in ipv6
                cvar.tcp_ip_length = cvar.tcp_ip_length + 0

            cvar.tcp_length = cvar.tcp_length + int(packet_dict["tcp.len"])
            self.count_services(services, cvar)
            cvar.num_tcp += 1
            self.accumulate_IDs(ID, cvar)
            self.accumulate_ports([packet_dict["tcp.srcport"], packet_dict["tcp.dstport"]], cvar)

        elif Prot1 == "udp":
            cvar.udp_frame_length = cvar.udp_frame_length + int(packet_dict["frame.len"])
            try:
                cvar.udp_ip_length = cvar.udp_ip_length + int(packet_dict["ip.len"])
            except KeyError:  # does not exist in ipv6
                cvar.udp_ip_length = cvar.udp_ip_length + 0

            cvar.udp_length = cvar.udp_length + int(packet_dict["udp.length"])
            self.count_services(services, cvar)
            cvar.num_udp += 1
            self.accumulate_IDs(ID, cvar)
            self.accumulate_ports([packet_dict["udp.srcport"], packet_dict["udp.dstport"]], cvar)

        elif Prot1 == "igmp":
            cvar.num_igmp += 1

    def count_services(self, slist, cvar):
        if "http" in slist:
            cvar.num_http += 1

        if "tls" in slist:
            cvar.num_tls += 1

        elif "dns" in slist:
            cvar.num_dns += 1

        elif "dhcp" in slist:
            cvar.num_dhcp += 1

    def accumulate_IDs(self, ID, cvar):
        cvar.IDs.add(ID)

    def accumulate_ports(self, ports, cvar):
        cvar.ports.update(ports)

    def write_window(self, writer, one_record):
        end_time_seconds = datetime.utcfromtimestamp(one_record.window_end_time / 1000)
        print( "Window:", one_record.window_index, "PacketCount:", one_record.num_packets, "EndTime", end_time_seconds)
        record_for_csv = one_record.__dict__.copy()
        record_for_csv.pop("IDs", None)
        record_for_csv.pop("ports", None)
        record_for_csv.pop("window_index", None)
        record_for_csv["num_connection_pairs"] = len(one_record.IDs)
        record_for_csv["num_ports"] = len(one_record.ports)
        writer.writerow(record_for_csv)

    def reset_window(self, time_window_end, window_index):
        cvar = windowcounts(time_window_end=time_window_end, window_index=window_index + 1)
        return cvar
