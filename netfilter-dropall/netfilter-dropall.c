#include <linux/module.h>
#include <linux/printk.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static unsigned int nf_hookfun(void *priv, struct sk_buff *skb,
                               const struct nf_hook_state *state);

static struct nf_hook_ops nfho = {
        .hook = &nf_hookfun,
        .pf = PF_INET,
        .priority = NF_IP_PRI_FIRST,
        .hooknum = NF_INET_PRE_ROUTING
};

int __init init_module(void)
{
        pr_info("Hello world!\n");
        nf_register_net_hook(&init_net, &nfho);

        return 0;
}

void __exit cleanup_module(void)
{
        pr_info("Goodbye world!\n");
        nf_unregister_net_hook(&init_net, &nfho);
}

static unsigned int nf_hookfun(void *priv, struct sk_buff *skb,
                               const struct nf_hook_state *state)
{
        pr_info("Received packet, dropping...\n");
        return NF_DROP;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bastian Engel");
