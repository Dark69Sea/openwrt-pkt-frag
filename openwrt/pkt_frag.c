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
#include <linux/string.h>
#include <linux/ctype.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OpenWrt Advanced DPI Bypass");
MODULE_DESCRIPTION("Advanced packet manipulation for DPI bypass: fragmentation, TLS ClientHello split, QUIC fragmentation, padding, fingerprint modification");
MODULE_VERSION("2.0");

static unsigned int frag_size = 512;
module_param(frag_size, uint, 0644);
MODULE_PARM_DESC(frag_size, "Base fragment size in bytes (default 512)");

static bool enable_tcp = true;
module_param(enable_tcp, bool, 0644);
MODULE_PARM_DESC(enable_tcp, "Enable TCP fragmentation");

static bool enable_udp = true;
module_param(enable_udp, bool, 0644);
MODULE_PARM_DESC(enable_udp, "Enable UDP fragmentation");

static bool enable_tls_frag = true;
module_param(enable_tls_frag, bool, 0644);
MODULE_PARM_DESC(enable_tls_frag, "Enable TLS ClientHello fragmentation");

static bool enable_quic_frag = true;
module_param(enable_quic_frag, bool, 0644);
MODULE_PARM_DESC(enable_quic_frag, "Enable QUIC/HTTP3 fragmentation");

static bool enable_padding = true;
module_param(enable_padding, bool, 0644);
MODULE_PARM_DESC(enable_padding, "Enable random padding");

static unsigned int padding_min = 0;
module_param(padding_min, uint, 0644);
MODULE_PARM_DESC(padding_min, "Minimum padding bytes (default 0)");

static unsigned int padding_max = 64;
module_param(padding_max, uint, 0644);
MODULE_PARM_DESC(padding_max, "Maximum padding bytes (default 64)");

static bool enable_fingerprint = true;
module_param(enable_fingerprint, bool, 0644);
MODULE_PARM_DESC(enable_fingerprint, "Enable TLS fingerprint modification");

static unsigned int tls_record_size = 1400;
module_param(tls_record_size, uint, 0644);
MODULE_PARM_DESC(tls_record_size, "Max TLS record size (default 1400)");

static struct nf_hook_ops nfho_ipv4_out;
static struct nf_hook_ops nfho_ipv6_out;

#define TLS_HANDSHAKE 0x16
#define TLS_CLIENT_HELLO 0x01
#define QUIC_INITIAL 0x00
#define QUIC_HANDSHAKE 0x02

static bool is_tls_client_hello(const u8 *data, unsigned int len)
{
    if (len < 6) return false;
    return data[0] == TLS_HANDSHAKE && data[5] == TLS_CLIENT_HELLO;
}

static bool is_quic_initial(const u8 *data, unsigned int len)
{
    if (len < 1) return false;
    u8 first = data[0];
    return (first & 0x80) && ((first & 0x30) == 0x00);
}

static unsigned int add_random_padding(struct sk_buff *skb, unsigned int offset, unsigned int max_pad)
{
    if (!enable_padding || padding_max == 0) return 0;
    
    unsigned int pad_len = padding_min;
    if (padding_max > padding_min) {
        get_random_bytes(&pad_len, sizeof(pad_len));
        pad_len = padding_min + (pad_len % (padding_max - padding_min + 1));
    }
    
    if (pad_len == 0) return 0;
    
    if (skb_tailroom(skb) < pad_len) {
        if (pskb_expand_head(skb, 0, pad_len, GFP_ATOMIC))
            return 0;
    }
    
    u8 *pad = skb_put(skb, pad_len);
    get_random_bytes(pad, pad_len);
    
    return pad_len;
}

static unsigned int modify_tls_fingerprint(u8 *data, unsigned int len)
{
    if (!enable_fingerprint || len < 43) return 0;
    
    u8 *ptr = data + 5;
    unsigned int session_id_len = ptr[34];
    ptr += 35 + session_id_len;
    
    if (ptr + 2 > data + len) return 0;
    u16 cipher_suites_len = ntohs(*(u16*)ptr);
    ptr += 2;
    
    if (ptr + cipher_suites_len > data + len) return 0;
    
    u16 *suites = (u16*)ptr;
    unsigned int num_suites = cipher_suites_len / 2;
    
    for (unsigned int i = 0; i < num_suites; i++) {
        u16 suite = ntohs(suites[i]);
        if (suite == 0x1301 || suite == 0x1302 || suite == 0x1303) {
            suites[i] = htons(suite ^ 0x0101);
        }
    }
    
    ptr += cipher_suites_len;
    if (ptr + 1 > data + len) return 0;
    
    u8 comp_len = *ptr++;
    ptr += comp_len;
    
    if (ptr + 2 > data + len) return 0;
    u16 ext_len = ntohs(*(u16*)ptr);
    ptr += 2;
    
    u8 *ext_end = ptr + ext_len;
    if (ext_end > data + len) return 0;
    
    while (ptr + 4 <= ext_end) {
        u16 ext_type = ntohs(*(u16*)ptr);
        u16 ext_len2 = ntohs(*(u16*)(ptr + 2));
        ptr += 4;
        
        if (ptr + ext_len2 > ext_end) break;
        
        if (ext_type == 0x0000) {
            if (ext_len2 > 0) {
                get_random_bytes(ptr, min(ext_len2, (unsigned int)32));
            }
        } else if (ext_type == 0x000b) {
            if (ext_len2 >= 2) {
                u16 *alpn_len = (u16*)ptr;
                *alpn_len = htons(ntohs(*alpn_len) ^ 0x0101);
            }
        }
        
        ptr += ext_len2;
    }
    
    return 1;
}

static struct sk_buff *create_fragment(struct sk_buff *skb, unsigned int hdr_len,
                                        unsigned int offset, unsigned int frag_len,
                                        bool is_last, bool is_ipv6)
{
    struct sk_buff *frag = skb_copy(skb, GFP_ATOMIC);
    if (!frag) return NULL;
    
    if (is_ipv6) {
        struct ipv6hdr *ip6h = ipv6_hdr(frag);
        ip6h->payload_len = htons(frag_len + (ip6h->payload_len ? ntohs(ip6h->payload_len) - (skb->len - hdr_len) : 0));
    } else {
        struct iphdr *iph = ip_hdr(frag);
        iph->tot_len = htons(hdr_len + frag_len);
        iph->frag_off = htons((offset / 8) | (is_last ? 0 : IP_MF));
        ip_send_check(iph);
    }
    
    skb_trim(frag, hdr_len + frag_len);
    return frag;
}

static unsigned int fragment_tls_records(struct sk_buff *skb, unsigned int hdr_len,
                                          unsigned int payload_offset, unsigned int payload_len,
                                          bool is_ipv6)
{
    u8 *payload = skb_network_header(skb) + hdr_len + payload_offset;
    
    if (payload_len < 5) return NF_ACCEPT;
    
    unsigned int processed = 0;
    unsigned int num_records = 0;
    struct sk_buff *frags[16];
    
    while (processed < payload_len && num_records < 16) {
        if (processed + 5 > payload_len) break;
        
        u8 content_type = payload[processed];
        u16 version = ntohs(*(u16*)(payload + processed + 1));
        u16 rec_len = ntohs(*(u16*)(payload + processed + 3));
        
        if (rec_len > 16384 || processed + 5 + rec_len > payload_len) break;
        
        if (content_type == TLS_HANDSHAKE && enable_tls_frag) {
            u8 *hs_data = payload + processed + 5;
            unsigned int hs_len = rec_len;
            
            if (hs_len > tls_record_size) {
                unsigned int split_point = tls_record_size;
                if (is_tls_client_hello(hs_data, hs_len)) {
                    split_point = min(tls_record_size, hs_len / 2);
                }
                
                unsigned int first_rec = 5 + split_point;
                unsigned int second_rec = 5 + (hs_len - split_point);
                
                unsigned int pad = add_random_padding(skb, hdr_len + payload_offset + processed + first_rec, padding_max);
                
                if (skb_cloned(skb) && !skb_unshare(skb, GFP_ATOMIC))
                    return NF_DROP;
                
                payload = skb_network_header(skb) + hdr_len + payload_offset;
                
                memmove(payload + processed + first_rec + pad,
                        payload + processed + first_rec,
                        hs_len - split_point);
                
                *(u16*)(payload + processed + 3) = htons(first_rec - 5 + pad);
                *(u16*)(payload + processed + first_rec + pad + 1) = *(u16*)(payload + processed + 1);
                *(u16*)(payload + processed + first_rec + pad + 3) = htons(hs_len - split_point);
                payload[processed + first_rec + pad] = content_type;
                
                payload_len += 5 + pad;
                processed += first_rec + pad;
                modify_tls_fingerprint(payload + processed, hs_len - split_point);
                continue;
            }
        }
        
        unsigned int pad = add_random_padding(skb, hdr_len + payload_offset + processed + 5 + rec_len, padding_max);
        if (pad > 0) {
            if (skb_cloned(skb) && !skb_unshare(skb, GFP_ATOMIC))
                return NF_DROP;
            payload = skb_network_header(skb) + hdr_len + payload_offset;
            memmove(payload + processed + 5 + rec_len + pad,
                    payload + processed + 5 + rec_len,
                    payload_len - (processed + 5 + rec_len));
            *(u16*)(payload + processed + 3) = htons(rec_len + pad);
            payload_len += pad;
        }
        
        processed += 5 + rec_len + pad;
        num_records++;
    }
    
    if (num_records > 0 && payload_len > frag_size) {
        return pkt_frag_ipv4_generic(skb, hdr_len, payload_offset, payload_len, is_ipv6);
    }
    
    return NF_ACCEPT;
}

static unsigned int pkt_frag_ipv4_generic(struct sk_buff *skb, unsigned int hdr_len,
                                           unsigned int payload_offset, unsigned int payload_len,
                                           bool is_ipv6)
{
    unsigned int num_frags = (payload_len + frag_size - 1) / frag_size;
    if (num_frags <= 1) return NF_ACCEPT;
    
    if (skb_cloned(skb) && !skb_unshare(skb, GFP_ATOMIC))
        return NF_DROP;
    
    for (unsigned int i = 1; i < num_frags; i++) {
        struct sk_buff *frag = create_fragment(skb, hdr_len + payload_offset,
                                                i * frag_size,
                                                min(frag_size, payload_len - i * frag_size),
                                                i == num_frags - 1, is_ipv6);
        if (!frag) return NF_DROP;
        
        nf_ct_attach(frag, skb);
        if (is_ipv6)
            ipv6_local_out(frag->dev_net, frag->sk, frag);
        else
            ip_local_out(frag->dev_net, frag->sk, frag);
    }
    
    return NF_STOLEN;
}

static unsigned int process_tcp_packet(struct sk_buff *skb, bool is_ipv6)
{
    unsigned int hdr_len = is_ipv6 ? sizeof(struct ipv6hdr) : ip_hdrlen(skb);
    struct tcphdr *tcph = tcp_hdr(skb);
    unsigned int tcp_hdr_len = tcph->doff * 4;
    unsigned int payload_offset = hdr_len + tcp_hdr_len;
    unsigned int payload_len = skb->len - payload_offset;
    
    if (payload_len < 5) return NF_ACCEPT;
    
    u8 *payload = skb_transport_header(skb) + tcp_hdr_len;
    
    if (is_tls_client_hello(payload, payload_len)) {
        if (enable_tls_frag) {
            modify_tls_fingerprint(payload, payload_len);
            add_random_padding(skb, payload_offset + payload_len, padding_max);
            
            if (payload_len > frag_size) {
                return fragment_tls_records(skb, hdr_len, payload_offset - hdr_len, payload_len, is_ipv6);
            }
        }
        return NF_ACCEPT;
    }
    
    if (enable_tcp && payload_len > frag_size) {
        return pkt_frag_ipv4_generic(skb, hdr_len, tcp_hdr_len, payload_len, is_ipv6);
    }
    
    return NF_ACCEPT;
}

static unsigned int process_udp_packet(struct sk_buff *skb, bool is_ipv6)
{
    unsigned int hdr_len = is_ipv6 ? sizeof(struct ipv6hdr) : ip_hdrlen(skb);
    struct udphdr *udph = udp_hdr(skb);
    unsigned int payload_offset = hdr_len + sizeof(struct udphdr);
    unsigned int payload_len = ntohs(udph->len) - sizeof(struct udphdr);
    
    if (payload_len < 1) return NF_ACCEPT;
    
    u8 *payload = skb_transport_header(skb) + sizeof(struct udphdr);
    
    if (is_quic_initial(payload, payload_len)) {
        if (enable_quic_frag && payload_len > frag_size) {
            add_random_padding(skb, payload_offset + payload_len, padding_max);
            return pkt_frag_ipv4_generic(skb, hdr_len, sizeof(struct udphdr), payload_len, is_ipv6);
        }
        return NF_ACCEPT;
    }
    
    if (enable_udp && payload_len > frag_size) {
        return pkt_frag_ipv4_generic(skb, hdr_len, sizeof(struct udphdr), payload_len, is_ipv6);
    }
    
    return NF_ACCEPT;
}

static unsigned int pkt_frag_hook(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    if (!skb || !skb_network_header(skb))
        return NF_ACCEPT;
    
    if (skb->protocol == htons(ETH_P_IP)) {
        struct iphdr *iph = ip_hdr(skb);
        if (enable_tcp && iph->protocol == IPPROTO_TCP)
            return process_tcp_packet(skb, false);
        if (enable_udp && iph->protocol == IPPROTO_UDP)
            return process_udp_packet(skb, false);
    } else if (skb->protocol == htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = ipv6_hdr(skb);
        if (enable_tcp && ip6h->nexthdr == IPPROTO_TCP)
            return process_tcp_packet(skb, true);
        if (enable_udp && ip6h->nexthdr == IPPROTO_UDP)
            return process_udp_packet(skb, true);
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

    pr_info("pkt_frag v2: loaded (frag=%u, tls=%d, quic=%d, pad=%d-%d, fp=%d)\n",
            frag_size, enable_tls_frag, enable_quic_frag,
            padding_min, padding_max, enable_fingerprint);
    return 0;
}

static void __exit pkt_frag_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho_ipv4_out);
    nf_unregister_net_hook(&init_net, &nfho_ipv6_out);
    pr_info("pkt_frag v2: unloaded\n");
}

module_init(pkt_frag_init);
module_exit(pkt_frag_exit);