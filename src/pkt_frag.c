#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/random.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OpenWrt Packet Fragmentation");
MODULE_DESCRIPTION("Packet fragmentation for DPI bypass");
MODULE_VERSION("1.0");

static unsigned int frag_size = 512;
module_param(frag_size, uint, 0644);
MODULE_PARM_DESC(frag_size, "Fragment size in bytes (default 512)");

static bool enable_tcp = true;
module_param(enable_tcp, bool, 0644);
MODULE_PARM_DESC(enable_tcp, "Enable TCP fragmentation");

static bool enable_udp = true;
module_param(enable_udp, bool, 0644);
MODULE_PARM_DESC(enable_udp, "Enable UDP fragmentation");

static struct nf_hook_ops nfho_ipv4_out;
static struct nf_hook_ops nfho_ipv6_out;

static unsigned int pkt_frag_ipv4(struct sk_buff *skb, unsigned int frag_sz)
{
    struct iphdr *iph = ip_hdr(skb);
    unsigned int payload_len = ntohs(iph->tot_len) - (iph->ihl * 4);
    unsigned int hdr_len = iph->ihl * 4;
    unsigned int num_frags = (payload_len + frag_sz - 1) / frag_sz;
    
    if (num_frags <= 1)
        return NF_ACCEPT;

    if (skb_cloned(skb) && !skb_unshare(skb, GFP_ATOMIC))
        return NF_DROP;

    iph = ip_hdr(skb);
    iph->frag_off = htons(IP_MF);
    iph->tot_len = htons(hdr_len + frag_sz);
    ip_send_check(iph);

    for (unsigned int i = 1; i < num_frags; i++) {
        struct sk_buff *frag = skb_copy(skb, GFP_ATOMIC);
        if (!frag)
            return NF_DROP;

        struct iphdr *fiph = ip_hdr(frag);
        unsigned int offset = i * frag_sz;
        unsigned int this_len = min(frag_sz, payload_len - offset);
        
        fiph->frag_off = htons((offset / 8) | (i == num_frags - 1 ? 0 : IP_MF));
        fiph->tot_len = htons(hdr_len + this_len);
        ip_send_check(fiph);
        
        skb_trim(frag, hdr_len + this_len);
        memmove(skb_transport_header(frag), 
                skb_transport_header(skb) + offset, this_len);
        
        nf_ct_attach(frag, skb);
        ip_local_out(frag->dev_net, frag->sk, frag);
    }

    skb_trim(skb, hdr_len + frag_sz);
    memmove(skb_transport_header(skb), skb_transport_header(skb), frag_sz);
    return NF_STOLEN;
}

static unsigned int pkt_frag_ipv6(struct sk_buff *skb, unsigned int frag_sz)
{
    struct ipv6hdr *ip6h = ipv6_hdr(skb);
    unsigned int payload_len = ntohs(ip6h->payload_len);
    unsigned int hdr_len = sizeof(struct ipv6hdr);
    unsigned int num_frags = (payload_len + frag_sz - 1) / frag_sz;
    
    if (num_frags <= 1)
        return NF_ACCEPT;

    if (skb_cloned(skb) && !skb_unshare(skb, GFP_ATOMIC))
        return NF_DROP;

    ip6h = ipv6_hdr(skb);
    ip6h->payload_len = htons(frag_sz);
    
    for (unsigned int i = 1; i < num_frags; i++) {
        struct sk_buff *frag = skb_copy(skb, GFP_ATOMIC);
        if (!frag)
            return NF_DROP;

        struct ipv6hdr *fip6h = ipv6_hdr(frag);
        unsigned int offset = i * frag_sz;
        unsigned int this_len = min(frag_sz, payload_len - offset);
        
        fip6h->payload_len = htons(this_len);
        skb_trim(frag, hdr_len + this_len);
        memmove(skb_transport_header(frag), 
                skb_transport_header(skb) + offset, this_len);
        
        nf_ct_attach(frag, skb);
        ipv6_local_out(frag->dev_net, frag->sk, frag);
    }

    skb_trim(skb, hdr_len + frag_sz);
    memmove(skb_transport_header(skb), skb_transport_header(skb), frag_sz);
    return NF_STOLEN;
}

static unsigned int pkt_frag_hook(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    if (!skb || !skb_network_header(skb))
        return NF_ACCEPT;

    switch (skb->protocol) {
    case htons(ETH_P_IP):
        if (enable_tcp || enable_udp) {
            struct iphdr *iph = ip_hdr(skb);
            if ((enable_tcp && iph->protocol == IPPROTO_TCP) ||
                (enable_udp && iph->protocol == IPPROTO_UDP))
                return pkt_frag_ipv4(skb, frag_size);
        }
        break;
    case htons(ETH_P_IPV6):
        if (enable_tcp || enable_udp) {
            struct ipv6hdr *ip6h = ipv6_hdr(skb);
            if ((enable_tcp && ip6h->nexthdr == IPPROTO_TCP) ||
                (enable_udp && ip6h->nexthdr == IPPROTO_UDP))
                return pkt_frag_ipv6(skb, frag_size);
        }
        break;
    }
    return NF_ACCEPT;
}

static int __init pkt_frag_init(void)
{
    nfho_ipv4_out.hook = pkt_frag_hook;
    nfho_ipv4_out.hooknum = NF_INET_POST_ROUTING;
    nfho_ipv4_out.pf = NFPROTO_IPV4;
    nfho_ipv4_out.priority = NF_IP_PRI_FIRST;
    
    nfho_ipv6_out.hook = pkt_frag_hook;
    nfho_ipv6_out.hooknum = NF_INET_POST_ROUTING;
    nfho_ipv6_out.pf = NFPROTO_IPV6;
    nfho_ipv6_out.priority = NF_IP6_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho_ipv4_out);
    nf_register_net_hook(&init_net, &nfho_ipv6_out);

    pr_info("pkt_frag: loaded (frag_size=%u, tcp=%d, udp=%d)\n",
            frag_size, enable_tcp, enable_udp);
    return 0;
}

static void __exit pkt_frag_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho_ipv4_out);
    nf_unregister_net_hook(&init_net, &nfho_ipv6_out);
    pr_info("pkt_frag: unloaded\n");
}

module_init(pkt_frag_init);
module_exit(pkt_frag_exit);