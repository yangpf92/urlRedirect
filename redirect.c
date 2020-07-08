#include <linux/device.h>
#include <linux/in.h>
#include <linux/inetdevice.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <net/sock.h>
#include <net/tcp.h>

/*
 * 重定向HTML的几种格式
 */
const char *http_redirect_header =
    "HTTP/1.1 302 Moved Permanently\r\n"
    "Location: http://%s\r\n"
    "Content-Type: text/html; charset=iso-8859-1\r\n"
    "Content-length: 0\r\n"
    "Cache-control: no-cache\r\n"
    "\r\n";

static char http_err_header[1024] = {0};  // 1536
static int http_err_headlen = 0;

//构建重定向url报文
int build_http_error_redirect_url(const char *url) {
  pr_err("%s: hdr len=%d, url len=%d\n", __func__, strlen(http_redirect_header),
         strlen(url));
  memset(http_err_header, 0, sizeof(http_err_header));
  http_err_headlen = snprintf(http_err_header, sizeof(http_err_header) - 1,
                              http_redirect_header, url);
  pr_err("%s: err url, http_err_header=[%s], len=%d\n", __func__,
         http_err_header, http_err_headlen);
  return 0;
}

//写法1: 构造一个新的报文
static int _http_err_send_redirect_pkt(struct sk_buff *skb, struct iphdr *iph,
                                       struct tcphdr *tcph, const char *data,
                                       int size) {
  struct sk_buff *nskb = NULL;
  struct iphdr *niph;
  struct tcphdr *ntcph;

  if (!skb || !iph || !tcph || !data || size <= 0) {
    printk("args empty! sz=%d", size);
    return -1;
  }

  // TODO:
  // 这里的构建一个新的skb，没有使用以前的skb，其实这里有两种写法，一个是用以前的skb，一个是新构建一个skb
  //个人认为这里直接改变原数据包可能是最简单的方式
  //分配alloc_skb 缓冲区
  nskb = alloc_skb(MAX_TCP_HEADER + size, GFP_ATOMIC);
  if (!nskb) {
    printk("failed alloc_skb! max hdr=%d, size=%d\n", MAX_TCP_HEADER, size);
    goto out;
  }

  // skb_reserve()在数据缓存区头部预留一定的空间
  skb_reserve(nskb, MAX_TCP_HEADER);

  skb_reset_network_header(nskb);
  niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
  niph->version = 4;
  niph->ihl = sizeof(struct iphdr) / 4;
  niph->tos = 0;
  niph->id = iph->id;
  niph->frag_off = htons(IP_DF);

  //协议为TCP协议s
  niph->protocol = IPPROTO_TCP;
  niph->check = 0;

  //填充目的地址和源地址
  niph->saddr = iph->saddr;
  niph->daddr = iph->daddr;

  // niph->ttl = sysctl_ip_default_ttl;
  niph->ttl = iph->ttl;
  // niph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + size);
  // niph->check = ip_fast_csum((unsigned char *)niph, niph->ihl);

  skb_set_transport_header(nskb, sizeof(struct iphdr));
  ntcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
  memset(ntcph, 0, sizeof(struct tcphdr));
  ntcph->source = tcph->source;
  ntcph->dest = tcph->dest;
  ntcph->doff = sizeof(struct tcphdr) / 4;
  ntcph->seq = tcph->seq;
  ntcph->ack_seq = tcph->ack_seq;
  ntcph->ack = 1;
  ntcph->psh = tcph->psh;
  ntcph->rst = !size;
  ntcph->window = tcph->window;
  ntcph->urg_ptr = 0;

  if (size) {
    skb_put(nskb, size);
    memcpy((char *)(ntcph + 1), data, size);
  }
  //填充tcp校验和
  /*
      TODO:
      TCP校验和是一个端到端的校验和，由发送端计算，然后由接收端验证。其目的是为了发现TCP首部和数据在发送端到
      接收端之间发生的任何改动。如果接收方检测到校验和有差错，则TCP段会被直接丢弃。
      TCP校验和覆盖TCP首部和TCP数据，而IP首部中的校验和只覆盖IP的首部，不覆盖IP数据报中的任何数据。
      TCP的校验和是必需的，而UDP的校验和是可选的。
      TCP和UDP计算校验和时，都要加上一个12字节的伪首部。

      TODO:个人认为这里应该使用
      struct inet_sock *inet = inet_sk(sk);
      struct tcphdr *th = tcp_hdr(skb);

      if (skb->ip_summed == CHECKSUM_PARTIAL) {
          th->check = ~tcp_v4_check(len, inet->saddr, inet->daddr, 0);
     //附加伪头进行校验 skb->csum_start = skb_transport_header(skb) - skb->head;
          skb->csum_offset = offsetof(struct tcphdr, check);
      } else {
          //完整的tcp校验和计算方法
          th->check = tcp_v4_check(len, inet->saddr, inet->daddr,
     csum_partial((char *)th, th->doff << 2, skb->csum));
      }
      TODO:详情请参考
     https://blog.csdn.net/gongjun12345/article/details/53576935
     https://www.cnblogs.com/super-king/p/3284884.html
     http://hustcat.github.io/checksum-in-kernel/
  */
  ntcph->check =
      ~tcp_v4_check(sizeof(struct tcphdr) + size, niph->saddr, niph->daddr, 0);
  nskb->ip_summed =
      CHECKSUM_PARTIAL;  //使用硬件校验和(关于校验和的赋值是很重要的)
  nskb->csum_start = skb_transport_header(nskb) - nskb->head;
  nskb->csum_offset = offsetof(struct tcphdr, check);

  //获取skb的路由缓存项
  // TODO: 对于转发包，这个选项应该不为空，
  // 这里是重新构建一个数据包所以按道理是应该进去的，也是有必要进行判断的
  // 对于修改已有的数据包，个人认为是不需要进行判断的 本人觉得这一步可以不需要
  if (skb_dst(skb)) {
    //将路由设置到nskb中
    skb_dst_set_noref(nskb, skb_dst(skb));
    printk("skb_dst_set_noref, dev=%s",
           skb_dst(skb) ? skb_dst(skb)->dev->name : "dst_null");
  }
  //填充tcp头部中的协议
  nskb->protocol = htons(ETH_P_IP);

  //重新查找路由
  if (ip_route_me_harder(nskb, RTN_UNSPEC)) {
    printk("%s: ip_route_me_harder fialed, can't find the skb route\n",
           __func__);
    goto out;
  }

  // printk("org dev %s, new dev %s\n", (skb->dev->name), (nskb->dev->name));
  //本地数据包发送
  // TODO: 为什么不用dev_queue_xmit函数
  /*
      在数据包转发流程中，Netfilter
     框架的IP_FORWARD节点会对转发数据包进行检查过滤；
      而对于本机上层发出的数据包，网络层通过注册到上层的*ip_local_out*函数接收数据处理，处理
     OK 进一步交由IP_LOCAL_OUT节点检测；
      对于即将发往下层的数据包，需要经过IP_POST_ROUTING节点处理；网络层处理结束，
      通过*dev_queue_xmit*函数将数据包交由 Linux
     内核中虚拟网络设备做进一步处理，从这里数据包即离开网络层进入到下一层；

      可以参考链接:https://zhuanlan.zhihu.com/p/93630586?from_voters_page=true
  */
  // TODO:自己构建的数据包需要调用ip_local_out发送
  ip_local_out(nskb);

  return 0;

out:
  if (nskb) kfree_skb(nskb);
  return -1;
}

int http_err_send_redirect(struct sk_buff *old_skb, struct iphdr *iph,
                           struct tcphdr *tcph) {
  int ret;

  if (!old_skb || !iph || !tcph) {
    printk("args empty!");
    return NF_ACCEPT;
  }

  ret = _http_err_send_redirect_pkt(old_skb, iph, tcph, http_err_header,
                                    http_err_headlen);
  if (ret < 0) {
    return NF_ACCEPT;
  }

  return NF_DROP;
}

static unsigned int url_redirect_cb(unsigned int hook, struct sk_buff *skb,
                                    const struct net_device *in,
                                    const struct net_device *out,
                                    int (*okfn)(struct sk_buff *)) {
  struct iphdr *iph = ip_hdr(skb);
  struct ethhdr *eth = eth_hdr(skb);
  struct tcphdr *tcph = NULL;
  struct udphdr *udph = NULL;
  unsigned int sip, dip;
  unsigned short source, dest;
  unsigned char *payload = NULL;
  int plen;

  if (!skb) return NF_ACCEPT;
  if (skb->pkt_type == PACKET_BROADCAST) return NF_ACCEPT;

  if (!eth) {
    return NF_ACCEPT;
  }

  if (!iph) {
    return NF_ACCEPT;
  }

  if ((skb->protocol == htons(ETH_P_8021Q) ||
       skb->protocol == htons(ETH_P_IP)) &&
      skb->len >= sizeof(struct ethhdr)) {
    if (skb->protocol == htons(ETH_P_8021Q)) {
      iph = (struct iphdr *)((u8 *)iph + 4);
    }

    //判断是否是IPV4的报文
    if (iph->version != 4) return NF_ACCEPT;

    // HTTP报文本质上是TCP报文
    if (iph->protocol == IPPROTO_TCP) {
      struct urlfilterList *purlf = NULL;
      int ret = -1;

      //获取TCP头部信息
      tcph = (struct tcphdr *)((unsigned char *)iph + iph->ihl * 4);
      if (!tcph->ack) {
        return NF_ACCEPT;
      }

      //获取TCP的端口号
      source = ntohs(tcph->source);
      if (source != 80) {
        return NF_ACCEPT;
      }
      //获取tcp数据区指针
      payload = (unsigned char *)tcph + tcph->doff * 4;
      //获取tcp数据区长度
      plen = ntohs(iph->tot_len) - iph->ihl * 4 - tcph->doff * 4;

// DEBUG信息
#if 0
            int i = 0;
            for (i = 0; i < plen; i++)
            {
                printk("%c ", payload[i]);
            }
            printk("\n");
#endif

      if (plen > 12 && payload[0] == 'H' && payload[1] == 'T' &&
          payload[2] == 'T' && payload[3] == 'P' && payload[4] == '/') {
        //判断是否是404报文
        if (payload[9] == '4' && payload[10] == '0' && payload[11] == '4') {
          printk("============== line is %d\n", __LINE__);
          ret = http_err_send_redirect(skb, iph, tcph);
          if (ret == NF_DROP) {
            printk("drop http err, error drop!");
            return NF_DROP;
          }
          // printk("drop http err, error drop! ret=%d", ret);
        }
      }
    }
  }
  return NF_ACCEPT;
}

// TODO:
// 因为是pc访问一个不存在的网页，收到包的时候是404，所以需要在DNAT做解析，PREROUTING链
/*
如果内网主机访问外网而经过路由时，源 IP 会发生改变，这种变更行为就是 SNAT
反之，当外网的数据经过路由发往内网主机时，数据包中的目的 IP (路由器上的公网 IP)
将修改为内网 IP，这种变更行为就是 DNAT
*/
static struct nf_hook_ops url_redirect_postrouting = {
    .hook = url_redirect_cb,
    .owner = THIS_MODULE,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static int __init redirect_init(void) {
  printk("============== line is %d\n", __LINE__);
  build_http_error_redirect_url("www.baidu.com");
  nf_register_hook(&url_redirect_postrouting);
}

static void __exit redirect_eixt(void) {
  printk("============== line is %d\n", __LINE__);
  nf_unregister_hook(&url_redirect_postrouting);
}

MODULE_LICENSE("GPL");
module_init(redirect_init);
module_exit(redirect_eixt);
