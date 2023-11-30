import re
import multiprocessing
import subprocess
import json


class PacketCapture(multiprocessing.Process):
    def __init__(self, tshark_program, input_file_name, outQ):
        multiprocessing.Process.__init__(self)
        self.tshark_program = tshark_program
        self.input_file_name = input_file_name
        self.outQ = outQ
        self.keymap = {}

    def run(self):
        if self.input_file_name is not None:
            cmd = "" + self.tshark_program + " -V -r " + self.input_file_name + " -T ek"
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1, shell=True, universal_newlines=True)
        num_read = 0

        while True:
            try:
                line = p.stdout.readline()
            except:
                continue
            if "layers" in line:
                num_read += 1
                json_obj = json.loads(line.strip())
                source_filter = json_obj["layers"]
                keyval = source_filter.items()
                a = self.unwrap(keyval)
                self.send_data(a)
            else:
                pass
            if not line and p.poll() is not None:
                self.send_data({})
                break
        p.stdout.close()
        p.wait()

    def send_data(self, dictionary):
        self.outQ.put(dictionary)

    # this function unwraps a multi level JSON object into a python dictionary with key value pairs

    def unwrap(self, keyval):
        newKeyval = {}
        for key1, value1 in keyval:
            if key1 not in self.keymap:
                massagedKey1 = (
                    re.sub(r"(\w+_)(\1)+", r"\1_", key1)
                    .replace("__", ".")
                    .replace("request_", "request.")
                    .replace("record_", "record.")
                    .replace("tcp_flags", "tcp.flags")
                    .replace("flags_", "flags.")
                    .replace("src_", "src.")
                    .replace("dst_", "dst.")
                )
                self.keymap[key1] = massagedKey1

            if isinstance(value1, (str, bool, list)):
                newKeyval[self.keymap[key1]] = value1
            elif value1 is None:
                pass
            else:
                newKeyval.update(self.unwrap(value1.items()))
        return newKeyval
