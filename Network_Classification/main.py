from detectors import *
from services import *
from counts import *
from capture import *
import argparse
import multiprocessing as mp


def main():
    time_window = 500  # msec
    input_file_name = None
    output_file_name = "dataset.csv"
    tshark_program = "tshark"

    global sharedQ
    sharedQ = mp.Queue()
    global serviceQ
    serviceQ = mp.Queue()
    global timesQ
    timesQ = mp.Queue()

    parser = argparse.ArgumentParser()
    parser.add_argument("--sourcefile", default=input_file_name)
    args = parser.parse_args()

    if args.sourcefile:
        input_file_name = args.sourcefile

    data_collect = PacketCapture(tshark_program, input_file_name, sharedQ)
    data_collect.start()

    data_process = PacketAnalyse(sharedQ, serviceQ)
    data_process.start()

    services_process = ServiceIdentity(serviceQ, timesQ)
    services_process.start()

    time_counts = TimesAndCounts(time_window, output_file_name, timesQ)
    time_counts.start()



if __name__ == "__main__":
    main()
