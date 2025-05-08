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

static __always_inline int handle_event(__u32 input_ip) {
    
    struct lpm_key lookup_key;
    lookup_key.prefixlen = 32;
    lookup_key.ip = input_ip;
    __u64 *lookup_value = lpm_trie_map.lookup(&lookup_key);
    if (lookup_value) {
        __u64 temp_lookup_value = *lookup_value + 1;
        bpf_trace_printk("Matched IP %x with count: %llu -> %llu\n", lookup_key.ip, *lookup_value, &temp_lookup_value);
        lpm_trie_map.update(&lookup_key, &temp_lookup_value);
    }
    
    return 0;
}

// XDP program: goal, verify that the LPM is working and figure out how to use it!

int xdp_prog_simple(struct xdp_md *ctx) {

    
    //First attempt to manually add something to the trie and set the count to 1 
    
    bpf_trace_printk("received packet");
    //extract the ip header from the incoming packet into iphdr
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // parse the ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
      bpf_trace_printk("failed to parse ethernet");
      return XDP_PASS; //pass packet if too short
    }

    //check if actually IP
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
      bpf_trace_printk("Failed to detect IP");
      return XDP_PASS;
    }

    //parse IP header
    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end) {
      bpf_trace_printk("IP is corrupted");
      return XDP_PASS; //pass packet if it is incomplete
    }
    
    handle_event(iph->saddr);
    
    
    // No match found, pass the packet
    return XDP_PASS;
    
    
}  


