#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/proc_fs.h>  /* Necessary because we use proc fs */
#include <linux/seq_file.h> /* for seq_file */
#include <asm/uaccess.h>    /* for copy_*_user */

/* mpls includes*/
// #include <linux/types.h>
// #include <linux/skbuff.h>
// #include <linux/net.h>
// #include <linux/module.h>
// #include <linux/mpls.h>
// #include <linux/vmalloc.h>
// #include <net/ip.h>
// #include <net/dst.h>
// #include <net/lwtunnel.h>
// #include <net/netevent.h>
// #include <net/netns/generic.h>
// #include <net/ip6_fib.h>
// #include <net/route.h>
// #include <net/mpls_iptunnel.h>
// #include <linux/mpls_iptunnel.h>
#include "internal.h"

// #define PTCP_WATCH_PORT     80  /* HTTP port */

static u32 inject_label_sender_address  = 0xC0A80164;  // 192.168.1.100

// #define MAX_NEW_LABELS 5

static struct nf_hook_ops nfho;

struct mpls_iptunnel_encap {
    u32 label[MAX_NEW_LABELS];
    u8  labels;
};

static unsigned int mpls_encap_size(struct mpls_iptunnel_encap *en)
{
    /* The size of the layer 2.5 labels to be added for this route */
    return en->labels * sizeof(struct mpls_shim_hdr);
}


static unsigned int ilabel_hook_func(const struct nf_hook_ops *ops,
                                   struct sk_buff *skb,
                                   const struct net_device *in,
                                   const struct net_device *out,
                                   int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph;          /* IPv4 header */
    struct tcphdr *tcph;        /* TCP header */
    u16 sport, dport;           /* Source and destination ports */
    u32 saddr, daddr;           /* Source and destination addresses */
    
    struct mpls_shim_hdr *hdr;
    u16 new_header_size;         /* MPLS header size*/
    u8 ttl;                     /* MPLS TTL(time to live)*/
    bool bos;                   /* MPLS bottom of stack */
    int i;

    // unsigned int hh_len;
    // struct dst_entry *dst = skb_dst(skb);

    struct mpls_iptunnel_encap tun_encap_info;

    /* Network packet is empty, seems like some problem occurred. Skip it */
    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);          /* get IP header */

    /* Skip if it's not TCP packet */
    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    tcph = tcp_hdr(skb);        /* get TCP header */

    /* Convert network endianness to host endiannes */
    saddr = ntohl(iph->saddr);
    daddr = ntohl(iph->daddr);
    sport = ntohs(tcph->source);
    dport = ntohs(tcph->dest);

    pr_debug("inject_label: saddr %pI4h ,  interset %pI4h\n", &saddr, &inject_label_sender_address);

    /* Watch only sender of interest */
    // if (saddr != inject_label_sender_address)
    //     return NF_ACCEPT;
    
    /* Create label struct */
    tun_encap_info.labels = 1;
    tun_encap_info.label[0] = 100;
    // tun_encap_info.label[1] = 31;
    // tun_encap_info.label[2] = 8;

    /* Calculate mpls header size */    
    new_header_size = mpls_encap_size(&tun_encap_info);

    /* Find the output device */
    // out_dev = dst->dev;
    // if (!mpls_output_possible(out_dev) ||
    //     !dst->lwtstate || skb_warn_if_lro(skb))
    //     goto drop;

    // skb_forward_csum(skb);
    
    /* Ensure there is enough space for the headers in the skb */
    // if (skb_cow(skb, hh_len + new_header_size)){
    //     pr_debug("inject_label: there is no enough space in skb");
    //     return NF_ACCEPT;
    // }
    
    skb_push(skb, new_header_size);
    skb_reset_network_header(skb);

    skb->protocol = htons(ETH_P_MPLS_UC);

    // /* Push the new labels */
    hdr = mpls_hdr(skb);
    bos = true;
    ttl = 255;  /* any value */

    pr_debug("inject_label: %d\n", tun_encap_info.labels);

    for (i = tun_encap_info.labels - 1; i >= 0; i--) {
        hdr[i] = mpls_entry_encode(tun_encap_info.label[i],
                       ttl, 0, bos);
        bos = false;
    }

    pr_debug("inject_label: %pI4h\n", &inject_label_sender_address);

    return NF_ACCEPT;
}


static int __init ilabel_init(void)
{
    int res;

    nfho.hook = (nf_hookfn *)ilabel_hook_func;    /* hook function */

    /* send packets */
    nfho.hooknum = NF_INET_POST_ROUTING;
    /* received packets */
    // nfho.hooknum = NF_INET_LOCAL_IN;
    
    nfho.pf = PF_INET;                          /* IPv4 */
    nfho.priority = NF_IP_PRI_FIRST;            /* max hook priority */

    res = nf_register_hook(&nfho);
    if (res < 0) {
        pr_err("inject_label: error in nf_register_hook()\n");
        return res;
    }

    pr_debug("inject_label: loaded\n");

    return 0;
}

static void __exit ilabel_exit(void)
{
    nf_unregister_hook(&nfho);
    pr_debug("inject_label: unloaded\n");
}

module_init(ilabel_init);
module_exit(ilabel_exit);

MODULE_AUTHOR("Ahmed Kamal");
MODULE_DESCRIPTION("Module for inject label");
MODULE_LICENSE("GPL");

