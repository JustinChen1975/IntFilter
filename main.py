from bcc import BPF
from ctypes import c_int, c_uint
from IPy import IP
import argparse
import json
import time
import os


mode_flag_map = {
    'xdpoffload': BPF.XDP_FLAGS_HW_MODE,
    'xdpdrv': BPF.XDP_FLAGS_DRV_MODE,
    'xdpgeneric': BPF.XDP_FLAGS_SKB_MODE
}

measure_item = ["total", "pass"]

def parse_arguments():
    parser = argparse.ArgumentParser(description='eBPF')

    parser.add_argument('--device_name', type=str, required=True, help="Specify the device.")
    parser.add_argument('--kernel_code', type=str, required=True, help="Specify C kernel code path.")
    parser.add_argument('--program', type=str, required=True,help="Specify program in kernel code")
    parser.add_argument('--mode', type=str, required=True, choices=['xdpoffload', 'xdpdrv', 'xdpgeneric'], help="Specify working mode")
    parser.add_argument('--operate', type=str, required=True, choices=['load', 'remove'], help="Load or remove")
    parser.add_argument('--config_file', type=str, required=True, help="Specify config file path")

    return parser.parse_args()


class config:
    def __init__(self, bpf_obj, args):
        self.bpf_obj = bpf_obj
        self.cfg_path = args.config_file
        self.modify_time = int(os.stat(args.config_file).st_mtime)
        self.args = args

    def load_cfg(self):
        with open(self.cfg_path, "r") as f:
            cfg_filters = json.load(f)

        cfg_keys = ['protocol', 'srcIP', 'dstIP', 'srcport', 'dstport']

        k_filters = self.bpf_obj.get_table("filters_map")
        for id, cfg_filter in enumerate(cfg_filters):
            k_filter = k_filters[id]

            if len(set(cfg_keys).intersection(set(cfg_filter.keys()))):
            # if 'srcIP' in cfg_filter or 'dstIP' in cfg_filter or 'protocol' in cfg_filter:
                k_filter.enable = 1
            else:
                k_filter.enable = 0

            # parse and set protocol
            protocol = cfg_filter.get('protocol')
            if protocol:
                k_filter.protocol_enable = 1
                k_filter.protocol = protocol
            else:
                k_filter.protocol_enable = 0
                k_filter.protocol = 0

            # parse and set src ip
            srcIP = cfg_filter.get('srcIP')
            if srcIP:
                k_filter.srcIP_enable = 1
                str_ip = IP(srcIP).strFullsize().split(':')
                k_filter.srcIP.seg0 = int(str_ip[0]+str_ip[1], 16)
                k_filter.srcIP.seg1 = int(str_ip[2]+str_ip[3], 16)
                k_filter.srcIP.seg2 = int(str_ip[4]+str_ip[5], 16)
                k_filter.srcIP.seg3 = int(str_ip[6]+str_ip[7], 16)
            else:
                k_filter.srcIP_enable = 0
                k_filter.srcIP.seg0 = 0
                k_filter.srcIP.seg1 = 0
                k_filter.srcIP.seg2 = 0
                k_filter.srcIP.seg3 = 0

            # parse and set dst ip
            dstIP = cfg_filter.get('dstIP')
            if dstIP:
                k_filter.dstIP_enable = 1
                str_ip = IP(dstIP).strFullsize().split(':')
                k_filter.dstIP.seg0 = int(str_ip[0]+str_ip[1], 16)
                k_filter.dstIP.seg1 = int(str_ip[2]+str_ip[3], 16)
                k_filter.dstIP.seg2 = int(str_ip[4]+str_ip[5], 16)
                k_filter.dstIP.seg3 = int(str_ip[6]+str_ip[7], 16)
            else:
                k_filter.dstIP_enable = 0
                k_filter.dstIP.seg0 = 0
                k_filter.dstIP.seg1 = 0
                k_filter.dstIP.seg2 = 0
                k_filter.dstIP.seg3 = 0
            
            # parse src port
            srcport = cfg_filter.get('srcport')
            if srcport:
                k_filter.srcport_enable = 1
                k_filter.srcport = srcport
            else:
                k_filter.srcport_enable = 0
                k_filter.srcport = 0
            
            # parse dst port
            dstport = cfg_filter.get('dstport')
            if dstport:
                k_filter.dstport_enable = 1
                k_filter.dstport = dstport
            else:
                k_filter.dstport_enable = 0
                k_filter.dstport = 0
                
            k_filters[id] = k_filter

    def renew(self):
        while True:
            if self.is_new():
                self.load_cfg()
                print("renew successfully!")
            time.sleep(1)
        
    def is_new(self):
        modify_time = int(os.stat(self.cfg_path).st_mtime)
        if modify_time == self.modify_time:
            return False
        else:
            self.modify_time = modify_time
            return True

    def print_measure_info(self):
        prev = [0] * 2
        while True:
            statpkt = self.bpf_obj.get_table("statpkt")
            for k in statpkt.keys():
                val = statpkt[k].value
                i = k.value
                delta = val - prev[i]
                prev[i] = val
                print("{}: {} pkt/s".format(measure_item[i], delta))
            print("")
            time.sleep(1)


def main():
    args = parse_arguments()

    device = args.device_name
    kernel_code = args.kernel_code
    program = args.program
    flags = mode_flag_map[args.mode]
    operate = args.operate

    offload_device = None
    if flags == BPF.XDP_FLAGS_HW_MODE:
        offload_device = device
    
    args.debug = False
    args.measure = True

    cflags = list()
    if args.debug:
        cflags += ["-Wall", "-DDEBUG"]
    if args.measure:
        cflags += ["-w", "-DMEASURE"]
    else:
        cflags += ["-w"]
    
    bpf_obj = BPF(src_file=kernel_code, cflags=cflags, device=offload_device)

    if operate == "load":
        fn = bpf_obj.load_func(program, BPF.XDP, offload_device)
        bpf_obj.attach_xdp(device, fn, flags=flags)
        print("Operate: {}\nDevice: {}\nKernel_code: {}\nProgram: {}\nMode: {}\n".format(operate, device, kernel_code, program, args.mode))
        
        cfg = config(bpf_obj, args)
        cfg.load_cfg()
        if args.debug:
            bpf_obj.trace_print()
        if args.measure:
            cfg.print_measure_info()
        cfg.renew()

    else:
        bpf_obj.remove_xdp(device, flags=flags)
        print("Operate: {}\nDevice: {}\nKernel_code: {}\nProgram: {}\nMode: {}\n".format(operate, device, kernel_code, program, args.mode))


if __name__ == "__main__":
    main()
