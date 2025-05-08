#!/usr/bin/env python3
from bcc import BPF
import sys
import ctypes
from time import sleep
import struct
import socket
import os  # For process forking
import subprocess

# Function to convert IP string to integer
def ip_to_int(ip_str):
    network_order = struct.unpack("!I", socket.inet_aton(ip_str))[0]
    host_order = socket.ntohl(network_order)
    return host_order

# Define ctypes structure for the LPM trie key
class LpmKey(ctypes.Structure):
    _fields_ = [
        ("prefixlen", ctypes.c_uint32),
        ("ip", ctypes.c_uint32),
    ]

class LpmValue(ctypes.Structure):
    _fields_ = [
        ("count", ctypes.c_uint32)
    ]

def dump_lpm_trie(map_ref):
    print("Dumping LPM trie contents:")
    for key, value in map_ref.items():
        reversed_ip = struct.unpack("<I", struct.pack("!I", key.ip))[0]
        ip = socket.inet_ntoa(struct.pack("!I", reversed_ip))
        count = value.value
        print(f"IP: {ip}/{key.prefixlen}, Count: {count}")

def insertIP(ip_string, map_ref, prefixlen=32):
    try:
        key = LpmKey(prefixlen=prefixlen, ip=ip_to_int(ip_string))
        value = LpmValue(count=14)  # Example count
        map_ref[key] = value
        print(f"Inserted entry for {ip_string}/{prefixlen} into LPM trie")
        return 0
    except Exception as e:
        print(f"Failed to insert {ip_string}/{prefixlen} into LPM trie: {e}")
        return -1

def load_rules_from_file(file_path, lpm_trie_map):
    """Load IP and prefix rules from a file into the LPM trie."""
    try:
        with open(file_path, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    ip = parts[0]
                    prefix = int(parts[1])
                    insertIP(ip, lpm_trie_map, prefix)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"Error reading file '{file_path}': {e}")

# Verify that a network interface is provided as an argument
if len(sys.argv) < 3:
    print("Usage: {} <network-interface> <mode> [rules-file] use -h or -help for more".format(sys.argv[0]))
    sys.exit(1)

interface = sys.argv[1]
mode = sys.argv[2]
file_path = sys.argv[3] if len(sys.argv) > 3 else None  # Optional file path argument

if mode == '-h' or mode == '-help':
    print("EECS Research LPM Trie tool.\n" + "-"*37 + "Modes" + "-"*38)
    print("Modes are combinations of actions:")
    print("  - 'a' for attach")
    print("  - 'd' for detach")
    print("  - 's' for status")
    print("  - 'v' for verbose (dumps LPM trie contents periodically)")
    print("  - 'm' for manual dump of LPM trie contents")
    print("  - 'h' or '-help' for help")
    print("When attaching ('a'), you must also specify one of:")
    print("  - 'r' for drop mode: drop all incoming packets.")
    print("  - 'p' for pass mode: pass all incoming packets.")
    print("  - 'e' for redirect mode: redirect all incoming packets back to the sender.")
    print("\nExamples:")
    print("  Attach and drop packets (verbose): '{} <interface> arv'".format(sys.argv[0]))
    print("  Attach and pass packets with rules file: '{} <interface> ap my_rules.txt'".format(sys.argv[0]))
    print("  Detach XDP program:                '{} <interface> d'".format(sys.argv[0]))
    print("  Show status:                       '{} <interface> s'".format(sys.argv[0]))
    print("  Manual dump of LPM trie:           '{} <interface> m'".format(sys.argv[0]))
    print("-"*79)
    sys.exit(0)
else:
    mode_set = set(mode)

    if 'a' in mode_set:
        action_mode = None
        for m in ['r', 'p', 'e']:
            if m in mode_set:
                action_mode = m
                break

        if action_mode is None:
            print("Error: When using 'a' mode, you must specify one of 'r', 'p', or 'e'.")
            sys.exit(1)

        verbose = 'v' in mode_set

        # Define the mapping for mode to XDP program files
        mode_to_xdp_prog = {
            'r': 'xdp_drop.c',     # Drop mode program
            'p': 'xdp_pass.c',     # Pass mode program
            'e': 'xdp_redirect.c'  # Redirect mode program
        }

        # Select the appropriate program based on the mode
        xdp_program = mode_to_xdp_prog[action_mode]

        # Load and attach the selected XDP program
        bpf = BPF(src_file=xdp_program, cflags=["-O2", "-Wall"])
        fn = bpf.load_func("xdp_prog_simple", BPF.XDP)
        bpf.attach_xdp(interface, fn, 0)

        print(f"XDP program '{xdp_program}' attached to {interface} with mode '{action_mode}'.")

        # Keep reference to the map for later access (e.g., for -m mode)
        lpm_trie_map = bpf.get_table("lpm_trie_map")

        # Load rules from file if provided
        if file_path:
            load_rules_from_file(file_path, lpm_trie_map)
        else:
            # Default entries if no file is provided
            insertIP("192.0.0.0", lpm_trie_map, 8)
            insertIP("172.22.0.0", lpm_trie_map, 16)
            insertIP("142.0.0.0", lpm_trie_map, 8)
            insertIP("8.0.0.0", lpm_trie_map, 8)

        if verbose:
            print("Verbose mode enabled. Press Ctrl-C to stop.")
            dump_lpm_trie(lpm_trie_map)
            try:
                while True:
                    sleep(5)
                    dump_lpm_trie(lpm_trie_map)
                    sys.stdout.flush()
            except KeyboardInterrupt:
                print("Detaching XDP program...")
                bpf.remove_xdp(interface, 0)
        else:
            # Fork the process to run in the background
            if os.fork() > 0:
                print("Running in silent mode in the background. Use '-d' to detach.")
                sys.exit(0)  # Parent process exits

            # Child process continues to run in the background
            try:
                while True:
                    sleep(60)
            except KeyboardInterrupt:
                print("Detaching XDP program...")
                bpf.remove_xdp(interface, 0)

    elif 'd' in mode_set:
        BPF.remove_xdp(interface, 0)
        print(f"XDP program detached from {interface}")

    elif 's' in mode_set:
        try:
            output = subprocess.check_output(["ip", "link", "show", interface], stderr=subprocess.STDOUT)
            print(output.decode())
        except subprocess.CalledProcessError as e:
            print(f"Failed to get status for {interface}: {e.output.decode()}")
            sys.exit(1)

    elif 'm' in mode_set:
        # Manual dump of the existing LPM trie contents without recompiling
        try:
            # Attach to the existing BPF object without recompiling
            bpf = BPF(text="")
            lpm_trie_map = bpf.get_table("lpm_trie_map")
            print("Manual dump of LPM trie contents:")
            dump_lpm_trie(lpm_trie_map)
        except Exception as e:
            print(f"Error while dumping LPM trie contents: {e}")
    else:
        print("Error: Invalid mode specified.")
        sys.exit(1)
