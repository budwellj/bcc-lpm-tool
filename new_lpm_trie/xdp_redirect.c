#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>

// Define the LPM trie map for IP lookup
struct lpm_key {
    __u32 prefixlen;  // Prefix length (e.g., /24 = 24, /32 = 32)
    __u32 ip;         // IP address
};

// Define the LPM trie map
BPF_LPM_TRIE(lpm_trie_map, struct lpm_key);

// Increment the count in the trie map if a match is found
static __always_inline int handle_event(__u32 input_ip) {
    struct lpm_key lookup_key = {.prefixlen = 32, .ip = input_ip};
    __u64 *lookup_value = lpm_trie_map.lookup(&lookup_key);
    if (lookup_value) {
        __u64 temp_lookup_value = *lookup_value + 1;
        bpf_trace_printk("Matched IP %x with count: %llu -> %llu\n", lookup_key.ip, *lookup_value, temp_lookup_value);
        lpm_trie_map.update(&lookup_key, &temp_lookup_value);
        return 1;
    } else {
        bpf_trace_printk("No match found in LPM for IP: %x\n", lookup_key.ip);
    }
    return 0;
}

// XDP program to verify LPM trie functionality and redirect matched packets

int xdp_prog_simple(struct xdp_md *ctx) {
    // Log packet receipt
    bpf_trace_printk("Received packet\n");

    // Extract the Ethernet header
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_trace_printk("Failed to parse Ethernet header\n");
        return XDP_PASS; // Pass the packet if too short
    }

    // Check if the packet is an IP packet
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        bpf_trace_printk("Not an IP packet\n");
        return XDP_PASS;
    }

    // Parse the IP header
    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end) {
        bpf_trace_printk("IP header is incomplete\n");
        return XDP_PASS;
    }

    // Log the source IP address
    bpf_trace_printk("Source IP: %x\n", iph->saddr);

    // Check the LPM map for the source IP address
    if (handle_event(iph->saddr) == 1) {
        // Log successful IP match and attempt to redirect
        bpf_trace_printk("IP found in LPM map, attempting to redirect\n");

        // Swap MAC addresses to redirect packet back to sender
        __u8 tmp_mac[ETH_ALEN];
        __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
        __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
        __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);

        // Log MAC address swap
        bpf_trace_printk("MAC addresses swapped, redirecting to ingress_ifindex\n");

        int redirect_result = bpf_redirect(ctx->ingress_ifindex, 0);
        bpf_trace_printk("Redirect result: %d\n", redirect_result);
        return redirect_result;
    }

    // No match found, pass the packet
    bpf_trace_printk("No IP match in LPM, passing packet\n");
    return XDP_PASS;
}


