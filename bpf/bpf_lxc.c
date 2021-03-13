// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2016-2020 Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <ep_config.h>
#include <node_config.h>

#include <bpf/verifier.h>

#include <linux/icmpv6.h>

#define EVENT_SOURCE LXC_ID

#include "lib/tailcall.h"
#include "lib/common.h"
#include "lib/config.h"
#include "lib/maps.h"
#include "lib/arp.h"
#include "lib/edt.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/icmp6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/l3.h"
#include "lib/lxc.h"
#include "lib/nat46.h"
#include "lib/identity.h"
#include "lib/policy.h"
#include "lib/lb.h"
#include "lib/drop.h"
#include "lib/dbg.h"
#include "lib/trace.h"
#include "lib/csum.h"
#include "lib/encap.h"
#include "lib/eps.h"
#include "lib/nat.h"
#include "lib/fib.h"
#include "lib/nodeport.h"
#include "lib/policy_log.h"

#if defined(ENABLE_ARP_PASSTHROUGH) && defined(ENABLE_ARP_RESPONDER)
#error "Either ENABLE_ARP_PASSTHROUGH or ENABLE_ARP_RESPONDER can be defined"
#endif

#if defined(ENABLE_IPV4) || defined(ENABLE_IPV6)
static __always_inline bool redirect_to_proxy(int verdict, __u8 dir)
{
	return is_defined(ENABLE_HOST_REDIRECT) && verdict > 0 &&
	       (dir == CT_NEW || dir == CT_ESTABLISHED ||  dir == CT_REOPENED);
}
#endif

#ifdef ENABLE_IPV6
static __always_inline int ipv6_l3_from_lxc(struct __ctx_buff *ctx,
					    struct ipv6_ct_tuple *tuple,
					    int l3_off, struct ipv6hdr *ip6,
					    __u32 *dstID)
{
#ifdef ENABLE_ROUTING
	union macaddr router_mac = NODE_MAC;
#endif
	int ret, verdict, l4_off, hdrlen;
	struct csum_offset csum_off = {};
	struct ct_state ct_state_new = {};
	struct ct_state ct_state = {};
	void *data, *data_end;
	union v6addr *daddr, orig_dip;
	__u32 tunnel_endpoint = 0;
	__u8 encrypt_key = 0;
	__u32 monitor = 0;
	__u8 reason;
	bool hairpin_flow = false; /* endpoint wants to access itself via service IP */
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;

	if (unlikely(!is_valid_lxc_src_ip(ip6)))
		return DROP_INVALID_SIP;

	ipv6_addr_copy(&tuple->daddr, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&tuple->saddr, (union v6addr *) &ip6->saddr);

	hdrlen = ipv6_hdrlen(ctx, l3_off, &tuple->nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = l3_off + hdrlen;

#ifndef ENABLE_HOST_SERVICES_FULL
	{
		struct lb6_service *svc;
		struct lb6_key key = {};

		ret = lb6_extract_key(ctx, tuple, l4_off, &key, &csum_off,
				      CT_EGRESS);
		if (IS_ERR(ret)) {
			if (ret == DROP_NO_SERVICE || ret == DROP_UNKNOWN_L4)
				goto skip_service_lookup;
			else
				return ret;
		}

		/*
		 * Check if the destination address is among the address that should
		 * be load balanced. This operation is performed before we go through
		 * the connection tracker to allow storing the reverse nat index in
		 * the CT entry for destination endpoints where we can't encode the
		 * state in the address.
		 */
        // 进行 cluster ip 解析
		svc = lb6_lookup_service(&key, is_defined(ENABLE_NODEPORT));
		if (svc) {
            // 数据包 完成 dnat 
			ret = lb6_local(get_ct_map6(tuple), ctx, l3_off, l4_off,
					&csum_off, &key, tuple, svc, &ct_state_new,
					false);
			if (IS_ERR(ret))
				return ret;
			hairpin_flow |= ct_state_new.loopback;
		}
	}

skip_service_lookup:
#endif /* !ENABLE_HOST_SERVICES_FULL */

	/* The verifier wants to see this assignment here in case the above goto
	 * skip_service_lookup is hit. However, in the case the packet
	 * is _not_ TCP or UDP we should not be using proxy logic anyways. For
	 * correctness it must be below the service handler in case the service
	 * logic re-writes the tuple daddr. In "theory" however the assignment
	 * should be OK to move above goto label.
	 */
	ipv6_addr_copy(&orig_dip, (union v6addr *) &tuple->daddr);


	/* WARNING: ip6 offset check invalidated, revalidate before use */

	/* Pass all outgoing packets through conntrack. This will create an
	 * entry to allow reverse packets and return set cb[CB_POLICY] to
	 * POLICY_SKIP if the packet is a reply packet to an existing incoming
	 * connection.
	 */
	ret = ct_lookup6(get_ct_map6(tuple), tuple, ctx, l4_off, CT_EGRESS,
			 &ct_state, &monitor);
	if (ret < 0)
		return ret;

	reason = ret;

	/* Check it this is return traffic to an ingress proxy. */
	if ((ret == CT_REPLY || ret == CT_RELATED) && ct_state.proxy_redirect) {
		/* Stack will do a socket match and deliver locally. */
		return ctx_redirect_to_proxy6(ctx, tuple, 0, false);
	}

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	/* Determine the destination category for policy fallback. */
	if (1) {
		struct remote_endpoint_info *info;

		info = lookup_ip6_remote_endpoint(&orig_dip);
		if (info != NULL && info->sec_label) {
			*dstID = info->sec_label;
			tunnel_endpoint = info->tunnel_endpoint;
			encrypt_key = get_min_encrypt_key(info->key);
		} else {
			*dstID = WORLD_ID;
		}

		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
			   orig_dip.p4, *dstID);
	}

	/* If the packet is in the establishing direction and it's destined
	 * within the cluster, it must match policy or be dropped. If it's
	 * bound for the host/outside, perform the CIDR policy check.
	 */
	verdict = policy_can_egress6(ctx, tuple, SECLABEL, *dstID,
				     &policy_match_type, &audited);
	if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0) {
		send_policy_verdict_notify(ctx, *dstID, tuple->dport,
					   tuple->nexthdr, POLICY_EGRESS, 1,
					   verdict, policy_match_type, audited);
		return verdict;
	}

	switch (ret) {
	case CT_NEW:
		send_policy_verdict_notify(ctx, *dstID, tuple->dport,
					   tuple->nexthdr, POLICY_EGRESS, 1,
					   verdict, policy_match_type, audited);
ct_recreate6:
		/* New connection implies that rev_nat_index remains untouched
		 * to the index provided by the loadbalancer (if it applied).
		 * Create a CT entry which allows to track replies and to
		 * reverse NAT.
		 */
		ct_state_new.src_sec_id = SECLABEL;
		ret = ct_create6(get_ct_map6(tuple), &CT_MAP_ANY6, tuple, ctx,
				 CT_EGRESS, &ct_state_new, verdict > 0);
		if (IS_ERR(ret))
			return ret;
		monitor = TRACE_PAYLOAD_LEN;
		break;

	case CT_REOPENED:
		send_policy_verdict_notify(ctx, *dstID, tuple->dport,
					   tuple->nexthdr, POLICY_EGRESS, 1,
					   verdict, policy_match_type, audited);
	case CT_ESTABLISHED:
		/* Did we end up at a stale non-service entry? Recreate if so. */
		if (unlikely(ct_state.rev_nat_index != ct_state_new.rev_nat_index))
			goto ct_recreate6;
		break;

	case CT_RELATED:
	case CT_REPLY:
		policy_mark_skip(ctx);

#ifdef ENABLE_NODEPORT
		/* See comment in handle_ipv4_from_lxc(). */
		if (ct_state.node_port) {
			ctx->tc_index |= TC_INDEX_F_SKIP_RECIRCULATION;
			ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_REVNAT);
			return DROP_MISSED_TAIL_CALL;
		}
# ifdef ENABLE_DSR
		if (ct_state.dsr) {
			ret = xlate_dsr_v6(ctx, tuple, l4_off);
			if (ret != 0)
				return ret;
		}
# endif /* ENABLE_DSR */
#endif /* ENABLE_NODEPORT */
		if (ct_state.rev_nat_index) {
			ret = lb6_rev_nat(ctx, l4_off, &csum_off,
					  ct_state.rev_nat_index, tuple, 0);
			if (IS_ERR(ret))
				return ret;

			/* A reverse translate packet is always allowed except
			 * for delivery on the local node in which case this
			 * marking is cleared again.
			 */
			policy_mark_skip(ctx);
		}
		break;

	default:
		return DROP_UNKNOWN_CT;
	}

	hairpin_flow |= ct_state.loopback;

	if (redirect_to_proxy(verdict, reason)) {
		/* Trace the packet before it is forwarded to proxy */
		send_trace_notify(ctx, TRACE_TO_PROXY, SECLABEL, 0,
				  0, 0, reason, monitor);
		return ctx_redirect_to_proxy6(ctx, tuple, verdict, false);
	}

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	daddr = (union v6addr *)&ip6->daddr;

	/* See handle_ipv4_from_lxc() re hairpin_flow */
	if (is_defined(ENABLE_ROUTING) || hairpin_flow) {
		struct endpoint_info *ep;

		/* Lookup IPv6 address, this will return a match if:
		 *  - The destination IP address belongs to a local endpoint managed by
		 *    cilium
		 *  - The destination IP address is an IP address associated with the
		 *    host itself.
		 */
		ep = lookup_ip6_endpoint(ip6);
		if (ep) {
#ifdef ENABLE_ROUTING
			if (ep->flags & ENDPOINT_F_HOST) {
#ifdef HOST_IFINDEX
				goto to_host;
#else
				return DROP_HOST_UNREACHABLE;
#endif
			}
#endif /* ENABLE_ROUTING */
			policy_clear_mark(ctx);
			return ipv6_local_delivery(ctx, l3_off, SECLABEL, ep,
						   METRIC_EGRESS, false);
		}
	}

	/* The packet goes to a peer not managed by this agent instance */
#ifdef ENCAP_IFINDEX
	{
		struct endpoint_key key = {};

		/* Lookup the destination prefix in the list of known
		 * destination prefixes. If there is a match, the packet will
		 * be encapsulated to that node and then routed by the agent on
		 * the remote node.
		 *
		 * IPv6 lookup key: daddr/96
		 */
		key.ip6.p1 = daddr->p1;
		key.ip6.p2 = daddr->p2;
		key.ip6.p3 = daddr->p3;
		key.family = ENDPOINT_KEY_IPV6;

		/* Three cases exist here either (a) the encap and redirect could
		 * not find the tunnel so fallthrough to nat46 and stack, (b)
		 * the packet needs IPSec encap so push ctx to stack for encap, or
		 * (c) packet was redirected to tunnel device so return.
		 */
		ret = encap_and_redirect_lxc(ctx, tunnel_endpoint, encrypt_key,
					     &key, SECLABEL, monitor);
		if (ret == IPSEC_ENDPOINT)
			goto encrypt_to_stack;
		else if (ret != DROP_NO_TUNNEL_ENDPOINT)
			return ret;
	}
#endif
#ifdef ENABLE_NAT46
	if (unlikely(ipv6_addr_is_mapped(daddr))) {
		ep_tail_call(ctx, CILIUM_CALL_NAT64);
		return DROP_MISSED_TAIL_CALL;
	}
#endif
	if (is_defined(ENABLE_REDIRECT_FAST))
		return redirect_direct_v6(ctx, l3_off, ip6);

	goto pass_to_stack;

#ifdef ENABLE_ROUTING
to_host:
	if (is_defined(HOST_REDIRECT_TO_INGRESS) ||
	    (is_defined(ENABLE_HOST_FIREWALL) && *dstID == HOST_ID)) {
		if (is_defined(HOST_REDIRECT_TO_INGRESS)) {
			union macaddr host_mac = HOST_IFINDEX_MAC;

			ret = ipv6_l3(ctx, l3_off, (__u8 *)&router_mac.addr,
				      (__u8 *)&host_mac.addr, METRIC_EGRESS);
			if (ret != CTX_ACT_OK)
				return ret;
		}

		send_trace_notify(ctx, TRACE_TO_HOST, SECLABEL, HOST_ID, 0,
				  HOST_IFINDEX, reason, monitor);
		return redirect(HOST_IFINDEX, BPF_F_INGRESS);
	}
#endif

pass_to_stack:
#ifdef ENABLE_ROUTING
	ret = ipv6_l3(ctx, l3_off, NULL, (__u8 *) &router_mac.addr, METRIC_EGRESS);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;
#endif

    // 会把 source identity 嵌入 ipv6 报头中
	if (ipv6_store_flowlabel(ctx, l3_off, SECLABEL_NB) < 0)
		return DROP_WRITE_ERROR;

#ifndef ENCAP_IFINDEX
#ifdef ENABLE_IPSEC
	if (encrypt_key && tunnel_endpoint) {
		set_encrypt_key_mark(ctx, encrypt_key);
#ifdef IP_POOLS
		set_encrypt_dip(ctx, tunnel_endpoint);
#endif
	} else
#endif
#endif
	{
#ifdef ENABLE_IDENTITY_MARK
		/* Always encode the source identity when passing to the stack.
		 * If the stack hairpins the packet back to a local endpoint the
		 * source identity can still be derived even if SNAT is
		 * performed by a component such as portmap.
		 */
		ctx->mark |= MARK_MAGIC_IDENTITY;
		set_identity_mark(ctx, SECLABEL);
#endif
	}

#ifdef ENCAP_IFINDEX
encrypt_to_stack:
#endif
	send_trace_notify(ctx, TRACE_TO_STACK, SECLABEL, *dstID, 0, 0,
			  reason, monitor);

	cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY, 0);

	return CTX_ACT_OK;
}

static __always_inline int handle_ipv6(struct __ctx_buff *ctx, __u32 *dstID)
{
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	/* Handle special ICMPv6 messages. This includes echo requests to the
	 * logical router address, neighbour advertisements to the router.
	 * All remaining packets are subjected to forwarding into the container.
	 */
    // 处理icmpv6
	if (unlikely(ip6->nexthdr == IPPROTO_ICMPV6)) {
		if (data + sizeof(*ip6) + ETH_HLEN + sizeof(struct icmp6hdr) > data_end)
			return DROP_INVALID;
        // 对于任意的 邻居请求，尝试 代理答复，包括 网关和其它endpoint的邻居请求。否则 ，丢弃
        // 对于 endpoint ip 的 icmp回显请求，直接代理答复
		ret = icmp6_handle(ctx, ETH_HLEN, ip6, METRIC_EGRESS);
		if (IS_ERR(ret))
			return ret;
	}

	/* Perform L3 action on the frame */
	tuple.nexthdr = ip6->nexthdr;
    // 这个函数中，会在 ipv6 报头中 嵌入 源identity
	return ipv6_l3_from_lxc(ctx, &tuple, ETH_HLEN, ip6, dstID);
}

declare_tailcall_if(__or(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
			 is_defined(DEBUG)), CILIUM_CALL_IPV6_FROM_LXC)
int tail_handle_ipv6(struct __ctx_buff *ctx)
{
	__u32 dstID = 0;
	int ret = handle_ipv6(ctx, &dstID);

	if (IS_ERR(ret)) {
		return send_drop_notify(ctx, SECLABEL, dstID, 0, ret,
					CTX_ACT_DROP, METRIC_EGRESS);
	}

	return ret;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline int handle_ipv4_from_lxc(struct __ctx_buff *ctx,
						__u32 *dstID)
{
	struct ipv4_ct_tuple tuple = {};
#ifdef ENABLE_ROUTING
	union macaddr router_mac = NODE_MAC;
#endif
	void *data, *data_end;
	struct iphdr *ip4;
	int ret, verdict, l3_off = ETH_HLEN, l4_off;
	struct csum_offset csum_off = {};
	struct ct_state ct_state_new = {};
	struct ct_state ct_state = {};
	__be32 orig_dip;
	__u32 tunnel_endpoint = 0;
	__u8 encrypt_key = 0;
	__u32 monitor = 0;
	__u8 reason;
	bool hairpin_flow = false; /* endpoint wants to access itself via service IP */
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;
	bool has_l4_header = false;

    // 从数据包中，ip4 提取出了 3层头，data提取出了3层的 payload
	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;
	has_l4_header = ipv4_has_l4_header(ip4);

	tuple.nexthdr = ip4->protocol;

	if (unlikely(!is_valid_lxc_src_ipv4(ip4)))
		return DROP_INVALID_SIP;

	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;

	l4_off = l3_off + ipv4_hdrlen(ip4);

#ifndef ENABLE_HOST_SERVICES_FULL
// 可能已经在 cgroup内完成了，所以，以下service 解析 可能已经不会执行
	{
		struct lb4_service *svc;
		struct lb4_key key = {};

        // 数据包 提取出了  源ip 和 目的端口  到 lb4_key key 结构体
        //  生成key 后，是用来 匹配 cilium_lb4_services map 的
        /*
        type Service4Key struct {
        	Address     types.IPv4 `align:"address"`
        	Port        uint16     `align:"dport"`
        	BackendSlot uint16     `align:"backend_slot"`
        	Proto       uint8      `align:"proto"`
        	Scope       uint8      `align:"scope"`
        	Pad         pad2uint8  `align:"pad"`
        }
        */
		ret = lb4_extract_key(ctx, ip4, l4_off, &key, &csum_off,
				      CT_EGRESS);
		if (IS_ERR(ret)) {
			if (ret == DROP_NO_SERVICE || ret == DROP_UNKNOWN_L4)
				goto skip_service_lookup;
			else
				return ret;
		}
        // 查询 cilium_lb4_services 或 cilium_lb4_services_v2 map 
        // 查询出是否 有相应 的 map value（其中指明了 后端endpoint的 id ）
		svc = lb4_lookup_service(&key, is_defined(ENABLE_NODEPORT));
		if (svc) {
            //  如果是新的 请求，完成 tuple 中 目的endpoint 的DNAT 解析 ，否则，可根据 链路追踪表 直接 dnat
            // 解析 affinity 的 service，或者以 random or meglev方式解析 普通service
            // 把 nat 的结果写入了数据包  
			ret = lb4_local(get_ct_map4(&tuple), ctx, l3_off, l4_off,
					&csum_off, &key, &tuple, svc, &ct_state_new,
					ip4->saddr, has_l4_header, false);
			if (IS_ERR(ret))
				return ret;
			hairpin_flow |= ct_state_new.loopback;
		}
	}

skip_service_lookup:
#endif /* !ENABLE_HOST_SERVICES_FULL */

    // 如果以上逻辑 没生效，那么 ，以下的代码 重新实现 dnat 的逻辑
    
	/* The verifier wants to see this assignment here in case the above goto
	 * skip_service_lookup is hit. However, in the case the packet
	 * is _not_ TCP or UDP we should not be using proxy logic anyways. For
	 * correctness it must be below the service handler in case the service
	 * logic re-writes the tuple daddr. In "theory" however the assignment
	 * should be OK to move above goto label.
	 */
	orig_dip = tuple.daddr;

	/* WARNING: ip4 offset check invalidated, revalidate before use */

	/* Pass all outgoing packets through conntrack. This will create an
	 * entry to allow reverse packets and return set cb[CB_POLICY] to
	 * POLICY_SKIP if the packet is a reply packet to an existing incoming
	 * connection.
	 */
    // 查询链路追踪信息
	ret = ct_lookup4(get_ct_map4(&tuple), &tuple, ctx, l4_off, CT_EGRESS,
			 &ct_state, &monitor);
	if (ret < 0)
		return ret;

	reason = ret;

	/* Check it this is return traffic to an ingress proxy. */
    //对于 已经建链的 数据，如果有L7 策略，则直接转发给 L7 代理
	if ((ret == CT_REPLY || ret == CT_RELATED) && ct_state.proxy_redirect) {
		/* Stack will do a socket match and deliver locally. */
        // 支持 2中方式，把数据包 重定向给 L7 代理：
        // 方式1：给数据包 打上 mark （随后，数据包经过宿主机的iptables的 tproxy规则，重定向给 L7 代理 ）
        // 方式2：使用 ebpf sk_assign()调用，把数据 直接重定向给 cilium_host ingress，即定向给 L7 代理
		return ctx_redirect_to_proxy4(ctx, &tuple, 0, false);
	}

	/* Determine the destination category for policy fallback. */
    // 解析目的ip 的 identity
	if (1) {
		struct remote_endpoint_info *info;

        // 查询 cilium_ipcache map
        // 通过目的ip，查询 目的endpoint 的信息
		info = lookup_ip4_remote_endpoint(orig_dip);
		if (info != NULL && info->sec_label) {
            //发送给集群内的
            // 获取 目的endpoint 的 id 信息
			*dstID = info->sec_label;
			tunnel_endpoint = info->tunnel_endpoint;
			encrypt_key = get_min_encrypt_key(info->key);
		} else {
            // 发送给集群外的
			*dstID = WORLD_ID;
		}

		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
			   orig_dip, *dstID);
	}

	/* If the packet is in the establishing direction and it's destined
	 * within the cluster, it must match policy or be dropped. If it's
	 * bound for the host/outside, perform the CIDR policy check.
	 */
    //实施 l3/L4 egress policy
    // 通过双方的identity 来查询 cilium_policy* map，看是否能够通信
	verdict = policy_can_egress4(ctx, &tuple, SECLABEL, *dstID,
				     &policy_match_type, &audited);

	if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0) {
		send_policy_verdict_notify(ctx, *dstID, tuple.dport,
					   tuple.nexthdr, POLICY_EGRESS, 0,
					   verdict, policy_match_type, audited);
		return verdict;
	}

	switch (ret) {
	case CT_NEW:
		send_policy_verdict_notify(ctx, *dstID, tuple.dport,
					   tuple.nexthdr, POLICY_EGRESS, 0,
					   verdict, policy_match_type, audited);
ct_recreate4:
		/* New connection implies that rev_nat_index remains untouched
		 * to the index provided by the loadbalancer (if it applied).
		 * Create a CT entry which allows to track replies and to
		 * reverse NAT.
		 */
		ct_state_new.src_sec_id = SECLABEL;
		/* We could avoid creating related entries for legacy ClusterIP
		 * handling here, but turns out that verifier cannot handle it.
		 */
        // 创建 链路追踪项 ， 以将来 追踪回复包，可用于 做unNat
		ret = ct_create4(get_ct_map4(&tuple), &CT_MAP_ANY4, &tuple, ctx,
				 CT_EGRESS, &ct_state_new, verdict > 0);
		if (IS_ERR(ret))
			return ret;
		break;

	case CT_REOPENED:
		send_policy_verdict_notify(ctx, *dstID, tuple.dport,
					   tuple.nexthdr, POLICY_EGRESS, 0,
					   verdict, policy_match_type, audited);
	case CT_ESTABLISHED:
		/* Did we end up at a stale non-service entry? Recreate if so. */
		if (unlikely(ct_state.rev_nat_index != ct_state_new.rev_nat_index))
			goto ct_recreate4;
		break;

	case CT_RELATED:
	case CT_REPLY:
		policy_mark_skip(ctx);

#ifdef ENABLE_NODEPORT
		/* This handles reply traffic for the case where the nodeport EP
		 * is local to the node. We'll redirect to bpf_host.c egress to
		 * perform the reverse DNAT.
		 */
        // 如果 当初别人 通过 nodePort 访问本endpoint，那么，现在本endpoint 进行了回复
        // 此时，直接 tail call bpf_host.c 的 CILIUM_CALL_IPV4_FROM_LXC，完成unNat ，redirect 给 物理网卡 发出
		if (ct_state.node_port) {
			ctx->tc_index |= TC_INDEX_F_SKIP_RECIRCULATION;
			ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_REVNAT);
			return DROP_MISSED_TAIL_CALL;
		}
# ifdef ENABLE_DSR
		if (ct_state.dsr) {
            // 对于 nodePort DSR 的 回复包，当初最初的 client 源ip和端口 记录到了cilium_snat_v4_external map，
            // 此时， 恢复  client 源ip和端口 到 数据包的 目的中，从而 dsr 返给client
			ret = xlate_dsr_v4(ctx, &tuple, l4_off, has_l4_header);
			if (ret != 0)
				return ret;
		}
# endif /* ENABLE_DSR */
#endif /* ENABLE_NODEPORT */

		if (ct_state.rev_nat_index) {
            // 查询 cilium_lb4_reverse_nat map，执行 unNat
			ret = lb4_rev_nat(ctx, l3_off, l4_off, &csum_off,
					  &ct_state, &tuple, 0, has_l4_header);
			if (IS_ERR(ret))
				return ret;
		}
		break;

	default:
		return DROP_UNKNOWN_CT;
	}

	hairpin_flow |= ct_state.loopback;

	if (redirect_to_proxy(verdict, reason)) {
		/* Trace the packet before it is forwarded to proxy */
		send_trace_notify(ctx, TRACE_TO_PROXY, SECLABEL, 0,
				  0, 0, reason, monitor);
        // 支持 2中方式，把数据包 重定向给 L7 代理：
        // 方式1：给数据包 打上 mark （随后，数据包经过宿主机的iptables的 tproxy规则，重定向给 L7 代理 ）
        // 方式2：使用 ebpf sk_assign()调用，把数据 直接重定向给 cilium_host ingress，即定向给 L7 代理
		return ctx_redirect_to_proxy4(ctx, &tuple, verdict, false);
	}

	/* After L4 write in port mapping: revalidate for direct packet access */
	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	orig_dip = ip4->daddr;

	/* Allow a hairpin packet to be redirected even if ENABLE_ROUTING is
	 * disabled. Otherwise, the packet will be dropped by the kernel if
	 * it is going to be routed via an interface it came from after it has
	 * been passed to the stack.
	 */
	if (is_defined(ENABLE_ROUTING) || hairpin_flow) {
		struct endpoint_info *ep;

		/* Lookup IPv4 address, this will return a match if:
		 *  - The destination IP address belongs to a local endpoint
		 *    managed by cilium
		 *  - The destination IP address is an IP address associated with the
		 *    host itself
		 *  - The destination IP address belongs to endpoint itself.
		 */
        // 查询 cilium_lxc map ， 是否能够命中 本地的 其它endpoint 或则 本地host ip
		ep = lookup_ip4_endpoint(ip4);
		if (ep) {
#ifdef ENABLE_ROUTING
			if (ep->flags & ENDPOINT_F_HOST) {
#ifdef HOST_IFINDEX
				goto to_host;
#else
				return DROP_HOST_UNREACHABLE;
#endif
			}
#endif /* ENABLE_ROUTING */
			policy_clear_mark(ctx);
            // 执行 policy ， 直接重定向到 本地 相关 endpoint的 lxc( 直接 基于 cilium_call_policy map 的 id ，执行 tail_call(ctx, POLICY_CALL_MAP, ep->lxc_id)  )
			return ipv4_local_delivery(ctx, l3_off, SECLABEL, ip4,
						   ep, METRIC_EGRESS, false);
		}
	}

#ifdef ENCAP_IFINDEX
	{
		struct endpoint_key key = {};

		key.ip4 = orig_dip & IPV4_MASK;
		key.family = ENDPOINT_KEY_IPV4;

        // 直接 redirect 到 隧道接口的 egress
        // 处理 vxlan隧道 和 ipsec
        // ！！！ 会把 source identity 嵌入 vxlan 封装的 VNI  ！！！
		ret = encap_and_redirect_lxc(ctx, tunnel_endpoint, encrypt_key,
					     &key, SECLABEL, monitor);
		if (ret == DROP_NO_TUNNEL_ENDPOINT)
			goto pass_to_stack;
		/* If not redirected noteably due to IPSEC then pass up to stack
		 * for further processing.
		 */
		else if (ret == IPSEC_ENDPOINT)
			goto encrypt_to_stack;
		/* This is either redirect by encap code or an error has
		 * occurred either way return and stack will consume ctx.
		 */
		else
			return ret;
	}
#endif
	if (is_defined(ENABLE_REDIRECT_FAST))
        // 向 本机外部转发
        // redirect 到 相关物理网卡的  egress
		return redirect_direct_v4(ctx, l3_off, ip4);

	goto pass_to_stack;

#ifdef ENABLE_ROUTING
to_host:
	if (is_defined(HOST_REDIRECT_TO_INGRESS) ||
	    (is_defined(ENABLE_HOST_FIREWALL) && *dstID == HOST_ID)) {
        // 如果发送目的是 本机，则直接发送至 相关物理网卡的 ingress
		if (is_defined(HOST_REDIRECT_TO_INGRESS)) {
			union macaddr host_mac = HOST_IFINDEX_MAC;
            // // 更新3层ttl ， 2层mac
			ret = ipv4_l3(ctx, l3_off, (__u8 *)&router_mac.addr,
				      (__u8 *)&host_mac.addr, ip4);
			if (ret != CTX_ACT_OK)
				return ret;
		}

		send_trace_notify(ctx, TRACE_TO_HOST, SECLABEL, HOST_ID, 0,
				  HOST_IFINDEX, reason, monitor);
		return redirect(HOST_IFINDEX, BPF_F_INGRESS);
	}
#endif

pass_to_stack:
#ifdef ENABLE_ROUTING
	ret = ipv4_l3(ctx, l3_off, NULL, (__u8 *) &router_mac.addr, ip4);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;
#endif
#ifndef ENCAP_IFINDEX
#ifdef ENABLE_IPSEC
	if (encrypt_key && tunnel_endpoint) {
		set_encrypt_key_mark(ctx, encrypt_key);
#ifdef IP_POOLS
		set_encrypt_dip(ctx, tunnel_endpoint);
#endif
	} else
#endif
#endif
	{
#ifdef ENABLE_IDENTITY_MARK
		/* Always encode the source identity when passing to the stack.
		 * If the stack hairpins the packet back to a local endpoint the
		 * source identity can still be derived even if SNAT is
		 * performed by a component such as portmap.
		 */
        // 数据包中 打上 identity mark ，方便后续处理
		ctx->mark |= MARK_MAGIC_IDENTITY;
		set_identity_mark(ctx, SECLABEL);
#endif
	}

#ifdef ENCAP_IFINDEX
encrypt_to_stack:
#endif
	send_trace_notify(ctx, TRACE_TO_STACK, SECLABEL, *dstID, 0, 0,
			  reason, monitor);
	cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY, 0);
	return CTX_ACT_OK;
}

declare_tailcall_if(__or(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
			 is_defined(DEBUG)), CILIUM_CALL_IPV4_FROM_LXC)
int tail_handle_ipv4(struct __ctx_buff *ctx)
{
	__u32 dstID = 0;
	int ret = handle_ipv4_from_lxc(ctx, &dstID);

	if (IS_ERR(ret))
		return send_drop_notify(ctx, SECLABEL, dstID, 0, ret,
					CTX_ACT_DROP, METRIC_EGRESS);

	return ret;
}

#ifdef ENABLE_ARP_RESPONDER
/*
 * ARP responder for ARP requests from container
 * Respond to IPV4_GATEWAY with NODE_MAC
 */
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_ARP)
int tail_handle_arp(struct __ctx_buff *ctx)
{
	union macaddr mac = NODE_MAC;
	union macaddr smac;
	__be32 sip;
	__be32 tip;

	/* Pass any unknown ARP requests to the Linux stack */
	if (!arp_validate(ctx, &mac, &smac, &sip, &tip))
		return CTX_ACT_OK;

	/*
	 * The endpoint is expected to make ARP requests for its gateway IP.
	 * Most of the time, the gateway IP configured on the endpoint is
	 * IPV4_GATEWAY but it may not be the case if after cilium agent reload
	 * a different gateway is chosen. In such a case, existing endpoints
	 * will have an old gateway configured. Since we don't know the IP of
	 * previous gateways, we answer requests for all IPs with the exception
	 * of the LXC IP (to avoid specific problems, like IP duplicate address
	 * detection checks that might run within the container).
	 */
	if (tip == LXC_IPV4)
		return CTX_ACT_OK;
    // redirect to lxc egress
	return arp_respond(ctx, &mac, tip, &smac, sip, 0);
}
#endif /* ENABLE_ARP_RESPONDER */
#endif /* ENABLE_IPV4 */

/* Attachment/entry point is ingress for veth, egress for ipvlan. */
__section("from-container")
int handle_xgress(struct __ctx_buff *ctx)
{
	__u16 proto;
	int ret;

	bpf_clear_meta(ctx);
    // 每个 pod 都有一个 唯一的 LXC_ID
    // LXC_ID 写入数据包的 ctx->queue_mapping (queue_mapping , 是实现 映射数据包 到 多队列网卡的某个队列 )
    // 这样。在本地host上可以一直追踪 数据包的 identity
	edt_set_aggregate(ctx, LXC_ID);

    // 写入到 cilium_metrics 和 map cilium_events 中
	send_trace_notify(ctx, TRACE_FROM_LXC, SECLABEL, 0, 0, 0, 0,
			  TRACE_PAYLOAD_LEN);

	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
         // 这个函数中，会在 ipv6 报头中 嵌入 源identity
		invoke_tailcall_if(__or(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
					is_defined(DEBUG)),
				   CILIUM_CALL_IPV6_FROM_LXC, tail_handle_ipv6);
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
        // 这个函数，会尝试 在 数据包的vxlan 封装中，VNI 嵌入 source identity
		invoke_tailcall_if(__or(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
					is_defined(DEBUG)),
				   CILIUM_CALL_IPV4_FROM_LXC, tail_handle_ipv4);
		break;
#ifdef ENABLE_ARP_PASSTHROUGH
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
#elif defined(ENABLE_ARP_RESPONDER)
	case bpf_htons(ETH_P_ARP):
        // arp 代理 回复 完 容器arp请求网关（宿主机上的cilium_host），直接 redirect 给 lxc 的 egress
		ep_tail_call(ctx, CILIUM_CALL_ARP);
		ret = DROP_MISSED_TAIL_CALL;
		break;
#endif /* ENABLE_ARP_RESPONDER */
#endif /* ENABLE_IPV4 */
	default:
		ret = DROP_UNKNOWN_L3;
	}

out:
	if (IS_ERR(ret))
		return send_drop_notify(ctx, SECLABEL, 0, 0, ret, CTX_ACT_DROP,
					METRIC_EGRESS);
	return ret;
}

#ifdef ENABLE_IPV6
static __always_inline int
ipv6_policy(struct __ctx_buff *ctx, int ifindex, __u32 src_label, __u8 *reason,
	    struct ipv6_ct_tuple *tuple_out, __u16 *proxy_port, bool from_host)
{
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct csum_offset csum_off = {};
	int ret, l4_off, verdict, hdrlen;
	struct ct_state ct_state = {};
	struct ct_state ct_state_new = {};
	bool skip_ingress_proxy = false;
	union v6addr orig_sip;
	__u32 monitor = 0;
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	policy_clear_mark(ctx);
	tuple.nexthdr = ip6->nexthdr;

	ipv6_addr_copy(&tuple.daddr, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *) &ip6->saddr);
	ipv6_addr_copy(&orig_sip, (union v6addr *) &ip6->saddr);

	/* If packet is coming from the ingress proxy we have to skip
	 * redirection to the ingress proxy as we would loop forever.
	 */
	skip_ingress_proxy = tc_index_skip_ingress_proxy(ctx);

	hdrlen = ipv6_hdrlen(ctx, ETH_HLEN, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = ETH_HLEN + hdrlen;
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

	ret = ct_lookup6(get_ct_map6(&tuple), &tuple, ctx, l4_off, CT_INGRESS,
			 &ct_state, &monitor);
	if (ret < 0)
		return ret;

	*reason = ret;

	/* Check it this is return traffic to an egress proxy.
	 * Do not redirect again if the packet is coming from the egress proxy.
	 */
	if ((ret == CT_REPLY || ret == CT_RELATED) && ct_state.proxy_redirect &&
	    !tc_index_skip_egress_proxy(ctx)) {
		/* This is a reply, the proxy port does not need to be embedded
		 * into ctx->mark and *proxy_port can be left unset.
		 */
		send_trace_notify6(ctx, TRACE_TO_PROXY, src_label, SECLABEL, &orig_sip,
				  0, ifindex, 0, monitor);
		if (tuple_out)
			memcpy(tuple_out, &tuple, sizeof(tuple));
		return POLICY_ACT_PROXY_REDIRECT;
	}

	if (unlikely(ct_state.rev_nat_index)) {
		int ret2;

		ret2 = lb6_rev_nat(ctx, l4_off, &csum_off,
				   ct_state.rev_nat_index, &tuple, 0);
		if (IS_ERR(ret2))
			return ret2;
	}

	verdict = policy_can_access_ingress(ctx, src_label, SECLABEL,
					    tuple.dport, tuple.nexthdr, false,
					    &policy_match_type, &audited);

	/* Reply packets and related packets are allowed, all others must be
	 * permitted by policy.
	 */
	if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0) {
		send_policy_verdict_notify(ctx, src_label, tuple.dport,
					   tuple.nexthdr, POLICY_INGRESS, 1,
					   verdict, policy_match_type, audited);
		return verdict;
	}

	if (skip_ingress_proxy)
		verdict = 0;

	if (ret == CT_NEW || ret == CT_REOPENED) {
		send_policy_verdict_notify(ctx, src_label, tuple.dport,
					   tuple.nexthdr, POLICY_INGRESS, 1,
					   verdict, policy_match_type, audited);
	}

	if (ret == CT_NEW) {
#ifdef ENABLE_DSR
	{
		bool dsr = false;

		ret = handle_dsr_v6(ctx, &dsr);
		if (ret != 0)
			return ret;

		ct_state_new.dsr = dsr;
	}
#endif /* ENABLE_DSR */

		ct_state_new.src_sec_id = src_label;
		ct_state_new.node_port = ct_state.node_port;
		ct_state_new.ifindex = ct_state.ifindex;
		ret = ct_create6(get_ct_map6(&tuple), &CT_MAP_ANY6, &tuple, ctx, CT_INGRESS,
				 &ct_state_new, verdict > 0);
		if (IS_ERR(ret))
			return ret;

		/* NOTE: tuple has been invalidated after this */
	}

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	if (redirect_to_proxy(verdict, *reason)) {
		*proxy_port = verdict;
		send_trace_notify6(ctx, TRACE_TO_PROXY, src_label, SECLABEL, &orig_sip,
				  0, ifindex, *reason, monitor);
		if (tuple_out)
			memcpy(tuple_out, &tuple, sizeof(tuple));
		return POLICY_ACT_PROXY_REDIRECT;
	}
	/* Not redirected to host / proxy. */
	send_trace_notify6(ctx, TRACE_TO_LXC, src_label, SECLABEL, &orig_sip,
			   LXC_ID, ifindex, *reason, monitor);

	ifindex = ctx_load_meta(ctx, CB_IFINDEX);
	if (ifindex)
		return redirect_ep(ifindex, from_host);

	return CTX_ACT_OK;
}

declare_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
		    CILIUM_CALL_IPV6_TO_LXC_POLICY_ONLY)
int tail_ipv6_policy(struct __ctx_buff *ctx)
{
	struct ipv6_ct_tuple tuple = {};
	int ret, ifindex = ctx_load_meta(ctx, CB_IFINDEX);
	__u32 src_label = ctx_load_meta(ctx, CB_SRC_LABEL);
	bool from_host = ctx_load_meta(ctx, CB_FROM_HOST);
	__u16 proxy_port = 0;
	__u8 reason = 0;

	ctx_store_meta(ctx, CB_SRC_LABEL, 0);
	ctx_store_meta(ctx, CB_FROM_HOST, 0);

	ret = ipv6_policy(ctx, ifindex, src_label, &reason, &tuple,
			  &proxy_port, from_host);
	if (ret == POLICY_ACT_PROXY_REDIRECT)
		ret = ctx_redirect_to_proxy6(ctx, &tuple, proxy_port, from_host);
	if (IS_ERR(ret))
		return send_drop_notify(ctx, src_label, SECLABEL, LXC_ID,
					ret, CTX_ACT_DROP, METRIC_INGRESS);

	/* Store meta: essential for proxy ingress, see bpf_host.c */
	ctx_store_meta(ctx, CB_PROXY_MAGIC, ctx->mark);
	return ret;
}

declare_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
		    CILIUM_CALL_IPV6_TO_ENDPOINT)
int tail_ipv6_to_endpoint(struct __ctx_buff *ctx)
{
	__u32 src_identity = ctx_load_meta(ctx, CB_SRC_LABEL);
	void *data, *data_end;
	struct ipv6hdr *ip6;
	__u16 proxy_port = 0;
	__u8 reason;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
		ret = DROP_INVALID;
		goto out;
	}

	/* Packets from the proxy will already have a real identity. */
	if (identity_is_reserved(src_identity)) {
		union v6addr *src = (union v6addr *) &ip6->saddr;
		struct remote_endpoint_info *info;

		info = lookup_ip6_remote_endpoint(src);
		if (info != NULL) {
			__u32 sec_label = info->sec_label;

			if (sec_label) {
				/* When SNAT is enabled on traffic ingressing
				 * into Cilium, all traffic from the world will
				 * have a source IP of the host. It will only
				 * actually be from the host if "src_identity"
				 * (passed into this function) reports the src
				 * as the host. So we can ignore the ipcache
				 * if it reports the source as HOST_ID.
				 */
				if (sec_label != HOST_ID)
					src_identity = sec_label;
			}
		}
		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
			   ((__u32 *) src)[3], src_identity);
	}

	cilium_dbg(ctx, DBG_LOCAL_DELIVERY, LXC_ID, SECLABEL);

#ifdef LOCAL_DELIVERY_METRICS
	update_metrics(ctx_full_len(ctx), METRIC_INGRESS, REASON_FORWARDED);
#endif
	ctx_store_meta(ctx, CB_SRC_LABEL, 0);

	ret = ipv6_policy(ctx, 0, src_identity, &reason, NULL,
			  &proxy_port, true);
	if (ret == POLICY_ACT_PROXY_REDIRECT)
		ret = ctx_redirect_to_proxy_hairpin(ctx, proxy_port);
out:
	if (IS_ERR(ret))
		return send_drop_notify(ctx, src_identity, SECLABEL, LXC_ID,
					ret, CTX_ACT_DROP, METRIC_INGRESS);
	return ret;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
static __always_inline int
ipv4_policy(struct __ctx_buff *ctx, int ifindex, __u32 src_label, __u8 *reason,
	    struct ipv4_ct_tuple *tuple_out, __u16 *proxy_port, bool from_host)
{
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	struct csum_offset csum_off = {};
	int ret, verdict, l3_off = ETH_HLEN, l4_off;
	struct ct_state ct_state = {};
	struct ct_state ct_state_new = {};
	bool skip_ingress_proxy = false;
	bool is_untracked_fragment = false;
	bool has_l4_header = false;
	__u32 monitor = 0;
	__be32 orig_sip;
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;
	has_l4_header = ipv4_has_l4_header(ip4);

	policy_clear_mark(ctx);
	tuple.nexthdr = ip4->protocol;

	/* If packet is coming from the ingress proxy we have to skip
	 * redirection to the ingress proxy as we would loop forever.
	 */
	skip_ingress_proxy = tc_index_skip_ingress_proxy(ctx);

	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;
	orig_sip = ip4->saddr;

	l4_off = l3_off + ipv4_hdrlen(ip4);
	if (has_l4_header)
		csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);
#ifndef ENABLE_IPV4_FRAGMENTS
	/* Indicate that this is a datagram fragment for which we cannot
	 * retrieve L4 ports. Do not set flag if we support fragmentation.
	 */
	is_untracked_fragment = ipv4_is_fragment(ip4);
#endif
    // 查询链路追踪 ， tuple 取出追踪项
	ret = ct_lookup4(get_ct_map4(&tuple), &tuple, ctx, l4_off, CT_INGRESS, &ct_state,
			 &monitor);
	if (ret < 0)
		return ret;

	*reason = ret;

	/* Check it this is return traffic to an egress proxy.
	 * Do not redirect again if the packet is coming from the egress proxy.
	 */
	relax_verifier();
	if ((ret == CT_REPLY || ret == CT_RELATED) && ct_state.proxy_redirect &&
	    !tc_index_skip_egress_proxy(ctx)) {
		/* This is a reply, the proxy port does not need to be embedded
		 * into ctx->mark and *proxy_port can be left unset.
		 */
		send_trace_notify4(ctx, TRACE_TO_PROXY, src_label, SECLABEL, orig_sip,
				  0, ifindex, 0, monitor);
		if (tuple_out)
			*tuple_out = tuple;
        // 函数返回后，将会 重定向给 proxy
		return POLICY_ACT_PROXY_REDIRECT;
	}

#ifdef ENABLE_NAT46
	if (ctx_load_meta(ctx, CB_NAT46_STATE) == NAT46) {
		ep_tail_call(ctx, CILIUM_CALL_NAT46);
		return DROP_MISSED_TAIL_CALL;
	}
#endif
	if (unlikely(ret == CT_REPLY && ct_state.rev_nat_index &&
		     !ct_state.loopback)) {
		int ret2;

        // 当初 本pod 访问 cluster ip 的回复包， 已经建立链接的， 做反向的 unNat
		ret2 = lb4_rev_nat(ctx, l3_off, l4_off, &csum_off,
				   &ct_state, &tuple,
				   REV_NAT_F_TUPLE_SADDR, has_l4_header);
		if (IS_ERR(ret2))
			return ret2;
	}

    // 实施 endpoint的 ingress policy
	verdict = policy_can_access_ingress(ctx, src_label, SECLABEL,
					    tuple.dport, tuple.nexthdr,
					    is_untracked_fragment,
					    &policy_match_type, &audited);

	/* Reply packets and related packets are allowed, all others must be
	 * permitted by policy.
	 */
	if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0) {
		send_policy_verdict_notify(ctx, src_label, tuple.dport,
					   tuple.nexthdr, POLICY_INGRESS, 0,
					   verdict, policy_match_type, audited);
		return verdict;
	}

	if (skip_ingress_proxy)
		verdict = 0;

	if (ret == CT_NEW || ret == CT_REOPENED) {
		send_policy_verdict_notify(ctx, src_label, tuple.dport,
					   tuple.nexthdr, POLICY_INGRESS, 0,
					   verdict, policy_match_type, audited);
	}

	if (ret == CT_NEW) {
#ifdef ENABLE_DSR
	{
		bool dsr = false;

        // 访问nodePort时，node进行了 nodeport解析，当开启了 DSR 模式后，nodePort DNAT了数据包，并把“最初发起访问nodePort的client的 源ip和源端口”信息 添加到了数据包的 IPv4 报头的 option 中
        // 此时，该数据包 进入了 容器的 lxc egress，我们进行如下处理：
        // 从 IPv4 报头的 option 中 提取出 最初发起访问nodePort的client的 源ip和源端口，
        // 创建 dsr 相关的 nat 转换记录到cilium_snat_v4_external map （ 将来，endpoint回复数据时，在 lxc ingress ebfp 就自动把 ip和端口恢复，这样就能直接dsr 回复给client ）
		ret = handle_dsr_v4(ctx, &dsr);
		if (ret != 0)
			return ret;

		ct_state_new.dsr = dsr;
	}
#endif /* ENABLE_DSR */

		ct_state_new.src_sec_id = src_label;
		ct_state_new.node_port = ct_state.node_port;
		ct_state_new.ifindex = ct_state.ifindex;
        // 创建链路追踪表
		ret = ct_create4(get_ct_map4(&tuple), &CT_MAP_ANY4, &tuple, ctx, CT_INGRESS,
				 &ct_state_new, verdict > 0);
		if (IS_ERR(ret))
			return ret;

		/* NOTE: tuple has been invalidated after this */
	}

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	if (redirect_to_proxy(verdict, *reason)) {
		*proxy_port = verdict;
		send_trace_notify4(ctx, TRACE_TO_PROXY, src_label, SECLABEL, orig_sip,
				  0, ifindex, *reason, monitor);
		if (tuple_out)
			*tuple_out = tuple;
		return POLICY_ACT_PROXY_REDIRECT;
	}
	/* Not redirected to host / proxy. */
	send_trace_notify4(ctx, TRACE_TO_LXC, src_label, SECLABEL, orig_sip,
			   LXC_ID, ifindex, *reason, monitor);

	ifindex = ctx_load_meta(ctx, CB_IFINDEX);
	if (ifindex)
		return redirect_ep(ifindex, from_host);

	return CTX_ACT_OK;
}

declare_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
		    CILIUM_CALL_IPV4_TO_LXC_POLICY_ONLY)
int tail_ipv4_policy(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {};
	int ret, ifindex = ctx_load_meta(ctx, CB_IFINDEX);
	__u32 src_label = ctx_load_meta(ctx, CB_SRC_LABEL);
	bool from_host = ctx_load_meta(ctx, CB_FROM_HOST);
	__u16 proxy_port = 0;
	__u8 reason = 0;

	ctx_store_meta(ctx, CB_SRC_LABEL, 0);
	ctx_store_meta(ctx, CB_FROM_HOST, 0);

    // 实施了 L3/L4 的 ingress policy ，对nodePort dsr信息进行记录
	ret = ipv4_policy(ctx, ifindex, src_label, &reason, &tuple,
			  &proxy_port, from_host);
	if (ret == POLICY_ACT_PROXY_REDIRECT)
		ret = ctx_redirect_to_proxy4(ctx, &tuple, proxy_port, from_host);
	if (IS_ERR(ret))
		return send_drop_notify(ctx, src_label, SECLABEL, LXC_ID,
					ret, CTX_ACT_DROP, METRIC_INGRESS);

	/* Store meta: essential for proxy ingress, see bpf_host.c */
	ctx_store_meta(ctx, CB_PROXY_MAGIC, ctx->mark);
	return ret;
}

declare_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
		    CILIUM_CALL_IPV4_TO_ENDPOINT)
int tail_ipv4_to_endpoint(struct __ctx_buff *ctx)
{
	__u32 src_identity = ctx_load_meta(ctx, CB_SRC_LABEL);
	void *data, *data_end;
	struct iphdr *ip4;
	__u16 proxy_port = 0;
	__u8 reason;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto out;
	}

	/* Packets from the proxy will already have a real identity. */
	if (identity_is_reserved(src_identity)) {
		struct remote_endpoint_info *info;

		info = lookup_ip4_remote_endpoint(ip4->saddr);
		if (info != NULL) {
			__u32 sec_label = info->sec_label;

			if (sec_label) {
				/* When SNAT is enabled on traffic ingressing
				 * into Cilium, all traffic from the world will
				 * have a source IP of the host. It will only
				 * actually be from the host if "src_identity"
				 * (passed into this function) reports the src
				 * as the host. So we can ignore the ipcache
				 * if it reports the source as HOST_ID.
				 */
				if (sec_label != HOST_ID)
					src_identity = sec_label;
			}
		}
		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
			   ip4->saddr, src_identity);
	}

	cilium_dbg(ctx, DBG_LOCAL_DELIVERY, LXC_ID, SECLABEL);

#ifdef LOCAL_DELIVERY_METRICS
	update_metrics(ctx_full_len(ctx), METRIC_INGRESS, REASON_FORWARDED);
#endif
	ctx_store_meta(ctx, CB_SRC_LABEL, 0);

    // 实施 L3/L4 ingress policy
    // 里边也处理了 dsr nodePort
	ret = ipv4_policy(ctx, 0, src_identity, &reason, NULL,
			  &proxy_port, true);
    // 返回结果 ret ： 如果流量不是从 ingress proxy 来的， 并且有L7过滤需要，则直接 把数据包  redirect to cilium_host ，转给envoy，实施pod 的 L7 ingress policy  ；
    // 如果流量 是从 ingress proxy 过来的，说明已经做过一次过来了，则 流量可进入pod
	if (ret == POLICY_ACT_PROXY_REDIRECT)
        // 如果需要， 把 数据包 重定向 代理，实施 L7 ingress policy .
        // redicrt 转给  cilium_host 的egress
		ret = ctx_redirect_to_proxy_hairpin(ctx, proxy_port);
out:
	if (IS_ERR(ret))
		return send_drop_notify(ctx, src_identity, SECLABEL, LXC_ID,
					ret, CTX_ACT_DROP, METRIC_INGRESS);
	return ret;
}
#endif /* ENABLE_IPV4 */

/* Handle policy decisions as the packet makes its way towards the endpoint.
 * Previously, the packet may have come from another local endpoint, another
 * endpoint in the cluster, or from the big blue room (as identified by the
 * contents of ctx / CB_SRC_LABEL. Determine whether the traffic may be
 * passed into the endpoint or if it needs further inspection by a userspace
 * proxy.
 */
__section_tail(CILIUM_MAP_POLICY, TEMPLATE_LXC_ID)
int handle_policy(struct __ctx_buff *ctx)
{
	__u32 src_label = ctx_load_meta(ctx, CB_SRC_LABEL);
	__u16 proto;
	int ret;

	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
				   CILIUM_CALL_IPV6_TO_LXC_POLICY_ONLY, tail_ipv6_policy);
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
				   CILIUM_CALL_IPV4_TO_LXC_POLICY_ONLY, tail_ipv4_policy);
		break;
#endif /* ENABLE_IPV4 */
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

out:
	if (IS_ERR(ret))
		return send_drop_notify(ctx, src_label, SECLABEL, LXC_ID,
					ret, CTX_ACT_DROP, METRIC_INGRESS);

	return ret;
}

#ifdef ENABLE_NAT46
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_NAT64)
int tail_ipv6_to_ipv4(struct __ctx_buff *ctx)
{
	int ret;

	ret = ipv6_to_ipv4(ctx, 14, LXC_IPV4);
	if (IS_ERR(ret))
		goto drop_err;

	cilium_dbg_capture(ctx, DBG_CAPTURE_AFTER_V64, ctx->ingress_ifindex);

	ctx_store_meta(ctx, CB_NAT46_STATE, NAT64);

	invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
			   CILIUM_CALL_IPV4_FROM_LXC, tail_handle_ipv4);
drop_err:
	return send_drop_notify(ctx, SECLABEL, 0, 0, ret, CTX_ACT_DROP,
				METRIC_EGRESS);
}

static __always_inline int handle_ipv4_to_ipv6(struct __ctx_buff *ctx)
{
	union v6addr dp = {};
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	BPF_V6(dp, LXC_IP);
	return ipv4_to_ipv6(ctx, ip4, 14, &dp);

}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_NAT46)
int tail_ipv4_to_ipv6(struct __ctx_buff *ctx)
{
	int ret;

	ret = handle_ipv4_to_ipv6(ctx);
	if (IS_ERR(ret))
		goto drop_err;

	cilium_dbg_capture(ctx, DBG_CAPTURE_AFTER_V46, ctx->ingress_ifindex);

	invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
			   CILIUM_CALL_IPV6_TO_LXC_POLICY_ONLY, tail_ipv6_policy);
drop_err:
	return send_drop_notify(ctx, SECLABEL, 0, 0, ret, CTX_ACT_DROP,
				METRIC_INGRESS);
}
#endif
BPF_LICENSE("GPL");

__section("to-container")
int handle_to_container(struct __ctx_buff *ctx)
{
	int ret, trace = TRACE_FROM_STACK;
	__u32 identity = 0;
	__u16 proto;

	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	bpf_clear_meta(ctx);

    // return from_proxy ? 
    // identity = source identity
	if (inherit_identity_from_host(ctx, &identity))
		trace = TRACE_FROM_PROXY;

	send_trace_notify(ctx, trace, identity, 0, 0,
			  ctx->ingress_ifindex, 0, TRACE_PAYLOAD_LEN);

	ctx_store_meta(ctx, CB_SRC_LABEL, identity);

	switch (proto) {
#if defined(ENABLE_ARP_PASSTHROUGH) || defined(ENABLE_ARP_RESPONDER)
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
#endif
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
				   CILIUM_CALL_IPV6_TO_ENDPOINT, tail_ipv6_to_endpoint);
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
        //数据包重定向给 L7 代理
        //实施 ingress policy
        //处理 dsr 转发的 nodePort流量：从数据包的 ip option中提取出 初始ip和nodePort ，创建 dsr 相关的 nat 转换记录（？ 将来，endpoint回复数据时，自动把 ip和端口恢复，这样就能直接dsr 回复给client ）
		invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
				   CILIUM_CALL_IPV4_TO_ENDPOINT, tail_ipv4_to_endpoint);
		break;
#endif /* ENABLE_IPV4 */
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

out:
	if (IS_ERR(ret))
		return send_drop_notify(ctx, identity, SECLABEL, LXC_ID,
					ret, CTX_ACT_DROP, METRIC_INGRESS);

	return ret;
}
