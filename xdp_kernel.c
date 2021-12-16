#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#define MAX_FILTERS 256
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)


struct IPV6 {
    uint32_t seg0;
    uint32_t seg1;
    uint32_t seg2;
    uint32_t seg3;
};

struct filter {
    uint8_t enable;
    uint8_t protocol_enable;
    uint8_t srcIP_enable;
    uint8_t dstIP_enable;
    uint8_t srcport_enable;
    uint8_t dstport_enable;
    uint8_t protocol;
    struct IPV6 srcIP;
    struct IPV6 dstIP;
    uint16_t srcport;
    uint16_t dstport;
};

BPF_ARRAY(filters_map, struct filter, MAX_FILTERS);

// measure  receive  pass
#ifdef MEASURE
BPF_ARRAY(statpkt, long, 2);
#endif


int xdp_program(struct xdp_md* ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr* ethhdr = data;
    struct ipv6hdr *iph6;
    struct tcphdr *tcph;
    struct udphdr *udph;
    
#ifdef MEASURE
    long* value;
    uint32_t index = 0;
    value = statpkt.lookup(&index);
    if (value)
        __sync_fetch_and_add(value, 1);
#endif

    // Check if the ethernet header is valid.
    if (unlikely(ethhdr + 1 > (struct ethhdr*)data_end)) {
        return XDP_DROP;
    }

    // Filter IPV6
    if (htons(ethhdr->h_proto) != ETH_P_IPV6) {
        return XDP_DROP;
        //return XDP_PASS;    // debug
    }

    iph6 = (data + sizeof(struct ethhdr));

    // Check if the ip header is valid.
    if (unlikely(iph6 + 1 > (struct ipv6hdr *)data_end)) {
        return XDP_DROP;
    }
    
    // debug
    // if(iph6->nexthdr == IPPROTO_ICMPV6)
    //    return XDP_PASS; 
    
    if(iph6->nexthdr != IPPROTO_TCP && iph6->nexthdr != IPPROTO_UDP){
        return XDP_DROP;
    } else {
        switch (iph6->nexthdr){
            case IPPROTO_TCP:
                tcph = (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
                if (tcph + 1 > (struct tcphdr *)data_end) {
                    return XDP_DROP;
                }
                break;

            case IPPROTO_UDP:
                udph = (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
                if (udph + 1 > (struct udphdr *)data_end) {
                    return XDP_DROP;
                }
                break;
        }
    }

    for (uint32_t i = 0; i < MAX_FILTERS; ++i) {
        uint32_t key = i;
        struct filter *filter = filters_map.lookup(&key);

        if(!filter) {
            break;
        }

        // Check if the rule is enabled.
        if (!filter->enable) {
            continue;
        }

        // Protocols
        if (filter->protocol_enable) {
            if (iph6->nexthdr != filter->protocol)
                continue;
        }

        // Source address.
        if (filter->srcIP_enable) {
            if (htonl(iph6->saddr.in6_u.u6_addr32[0]) != filter->srcIP.seg0 || 
                htonl(iph6->saddr.in6_u.u6_addr32[1]) != filter->srcIP.seg1 ||
                htonl(iph6->saddr.in6_u.u6_addr32[2]) != filter->srcIP.seg2 ||
                htonl(iph6->saddr.in6_u.u6_addr32[3]) != filter->srcIP.seg3) {
                continue;
            }
        }

        // Destination address.
        if (filter->dstIP_enable) {
            if (htonl(iph6->daddr.in6_u.u6_addr32[0]) != filter->dstIP.seg0 || 
                htonl(iph6->daddr.in6_u.u6_addr32[1]) != filter->dstIP.seg1 ||
                htonl(iph6->daddr.in6_u.u6_addr32[2]) != filter->dstIP.seg2 ||
                htonl(iph6->daddr.in6_u.u6_addr32[3]) != filter->dstIP.seg3) {
                continue;
            }
        }

        // Source port.
        if (filter->srcport_enable) {
            switch(iph6->nexthdr) {
                case IPPROTO_TCP:
                    if (htons(tcph->source) != filter->srcport)
                        continue;
                    break;

                case IPPROTO_UDP:
                    if (htons(udph->source) != filter->srcport)
                        continue;
                    break;
            }
        }

        // Destination port.
        if (filter->dstport_enable) {
            switch(iph6->nexthdr) {
                case IPPROTO_TCP:
                    if (htons(tcph->dest) != filter->dstport)
                        continue;
                    break;

                case IPPROTO_UDP:
                    if (htons(udph->dest) != filter->dstport)
                        continue;
                    break;
            }
        }

        // match the filter
#ifdef DEBUG
            bpf_trace_printk("pass:  \n");
            bpf_trace_printk("src0 %x \n", htonl(iph6->saddr.in6_u.u6_addr32[0]));
            bpf_trace_printk("src1 %x \n", htonl(iph6->saddr.in6_u.u6_addr32[1]));
            bpf_trace_printk("src2 %x \n", htonl(iph6->saddr.in6_u.u6_addr32[2]));
            bpf_trace_printk("src3 %x \n\n", htonl(iph6->saddr.in6_u.u6_addr32[3]));
            bpf_trace_printk("dst0 %x \n", htonl(iph6->daddr.in6_u.u6_addr32[0]));
            bpf_trace_printk("dst1 %x \n", htonl(iph6->daddr.in6_u.u6_addr32[1]));
            bpf_trace_printk("dst2 %x \n", htonl(iph6->daddr.in6_u.u6_addr32[2]));
            bpf_trace_printk("dst3 %x \n\n", htonl(iph6->daddr.in6_u.u6_addr32[3]));
            bpf_trace_printk("srcport %d \n", htons(udph->source));
            bpf_trace_printk("dstport %d \n\n", htons(udph->dest));
#endif 

#ifdef MEASURE
        index = 1;
        value = statpkt.lookup(&index);
        if (value)
            __sync_fetch_and_add(value, 1);
#endif
        return XDP_PASS;
    }

    // mismatch all filters
    return XDP_DROP;
}
