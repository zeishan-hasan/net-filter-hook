// #include <linux/init.h>
// #include <linux/module.h>
// #include <linux/kernel.h>
// #include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <linux/types.h>
#include <linux/inet.h>
// Headers from the kernel source code
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <net/protocol.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/wait.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv6.h>
#include <linux/inetdevice.h>
#include <linux/proc_fs.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/rcupdate.h>
#include <net/net_namespace.h>
#include <net/netfilter/nf_queue.h>
#include <net/sock.h>

static struct nf_hook_ops *nfhkops = NULL;
struct nf_bridge_info nfbro;
// My hook Function
static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	static int kount = 0;
	printk(KERN_INFO "*-*-*-*-* info: hfunc is called\n");

	struct iphdr *iph = NULL;
	struct udphdr *udph = NULL;
	kount++;
	if (!skb){
		printk(KERN_INFO "*-*-*-*-*-* status: skbuff is found empty\n");
		return NF_ACCEPT;
	}

	printk(KERN_INFO "*-*-*-*-*-* status: skbuff# %u contains data\n", kount);

	iph = ip_hdr(skb);
	printk(KERN_INFO "*-*-*-*-*-* status: extracted the header of skbuff\n");
	if (iph->protocol == IPPROTO_UDP) {
		printk(KERN_INFO "*-*-*-*-*-* status: captured skbuff protocol (IPPROTO_UDP): %u\n", iph->protocol);
		printk(KERN_INFO "*-*-*-*-*-* status: captured skbuff source address: %pI4\n", &(iph->saddr));
		printk(KERN_INFO "*-*-*-*-*-* status: captured skbuff destination address: %pI4\n", &(iph->daddr));
		udph = udp_hdr(skb);
		if (ntohs(udph->dest) == 53) {
			printk(KERN_INFO "*-*-*-*-*-* status: Destination of captured skbuff (udph->dest): %u\n", ntohs(udph->dest));
			return NF_ACCEPT;
		}
	}
	else if (iph->protocol == IPPROTO_TCP) {
		printk(KERN_INFO "*-*-*-*-*-* status: captured skbuff protocol (IPPROTO_TCP): %u\n", iph->protocol);
		printk(KERN_INFO "*-*-*-*-*-* status: captured skbuff source address: %pI4\n", &(iph->saddr));
		printk(KERN_INFO "*-*-*-*-*-* status: captured skbuff destination address: %pI4\n", &(iph->daddr));
		return NF_ACCEPT;
	}
	
	printk ("*-*-*-*-*-*-*-*- info: End of hfunc\n");
	
	return NF_DROP;
	// return 0;

}


static int __init LKM_init(void)
{
	printk (KERN_INFO "*-*-*-*-* status: Netfilter module is loaded\n");

	nfhkops = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	
	/* Initialize netfilter hook operations */
	nfhkops->hook 		= (nf_hookfn*)hfunc;		/* hook function */
	nfhkops->hooknum 	= NF_INET_PRE_ROUTING;		/* received packets */
	nfhkops->pf 		= PF_INET;					/* IPv4 */
	nfhkops->priority 	= NF_IP_PRI_FIRST;			/* max hook priority */
	
	nf_register_net_hook(&init_net, nfhkops);
	
	return 0;
}


static void __exit LKM_exit(void)
{
	printk (KERN_INFO "*-*-*-*-* status: Netfilter module is unloaded\n");

	nf_unregister_net_hook(&init_net, nfhkops);
	kfree(nfhkops);
}

module_init(LKM_init);
module_exit(LKM_exit);
MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("DEXTER");
