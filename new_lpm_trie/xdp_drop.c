#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>

// Define the BPF map (BCC syntax)
// Define the LPM trie map using BCC syntax

struct lpm_key {
    __u32 prefixlen;  // Prefix length (e.g., /24 = 24, /32 = 32)
    __u32 ip;         // IP address
};

BPF_LPM_TRIE(lpm_trie_map, struct lpm_key);


// XDP program: goal, verify that the LPM is working and figure out how to use it!

int xdp_prog_simple(struct xdp_md *ctx) {

    
    
    
    // No match found, pass the packet
    return XDP_PASS;
    
    
}  


