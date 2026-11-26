// SPDX-License-Identifier: GPL-2.0-only

#include <net/dsa.h>
#include <linux/delay.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/math64.h>
#include <linux/netdevice.h>
#include <linux/regmap.h>
#include <net/flow_offload.h>
#include <linux/list.h>
#include <linux/rhashtable.h>
#include <asm/mach-rtl-otto/mach-rtl-otto.h>

#include "mirror.h"
#include "pie.h"
#include "qos.h"
#include "otto_dsa.h"
#include "stats.h"
#include "tc.h"

/* The PIE entry of a rule of an ordered list, shared by every port the rule is on */
struct otto_tc_list {
	struct list_head node;
	struct pie_rule rule;
	u64 ports;
	u8 port_refs[57];
};

struct rtl83xx_flow {
	unsigned long cookie;
	struct rhash_head node;
	struct rcu_head rcu_head;
	struct otto_dsa_priv *priv;
	struct pie_rule rule;
	u32 flags;
	struct otto_tc_list *list;	/* a rule of an ordered list: its entry */
	int port;
};

#define RTL930X_BANDWIDTH_CTRL_EGRESS(port)	(0x7660 + (port * 16))
#define RTL930X_BANDWIDTH_CTRL_INGRESS(port)	(0x8068 + (port * 4))
#define RTL930X_BANDWIDTH_CTRL_QUEUE_SET0(port, queue) \
						(0x3C60 + ((port) * 384) + ((queue) * 8))
#define RTL930X_BANDWIDTH_CTRL_QUEUE_SET1(port, queue) \
						(0xE300 + (((port) - 24) * 96) + ((queue) * 8))
#define RTL930X_EGBW_LB_CTRL			0x78EC
#define RTL930X_EGBW_LB_CTRL_TOKEN		GENMASK(31, 16)
#define RTL930X_BANDWIDTH_CTRL_INGRESS_BURST_HIGH_ON(port) \
						(0x80DC + (port * 8))
#define RTL930X_BANDWIDTH_CTRL_INGRESS_BURST_HIGH_OFF(port) \
						(0x80E0 + (port * 8))
#define RTL930X_BANDWIDTH_CTRL_INGRESS_BURST_MAX \
						GENMASK(30, 0)

#define RTL931X_BANDWIDTH_CTRL_EGRESS(port)	(0x2164 + (port * 8))
#define RTL931X_BANDWIDTH_CTRL_INGRESS(port)	(0xe008 + (port * 8))

#define RTL93XX_BANDWIDTH_CTRL_RATE_MAX		GENMASK(19, 0)
#define RTL93XX_BANDWIDTH_CTRL_ENABLE		BIT(20)
#define RTL931X_BANDWIDTH_CTRL_MAX_BURST	GENMASK(15, 0)

#define RTL930X_INGRESS_FC_CTRL(port)		(0x81CC + ((port / 29) * 4))
#define RTL930X_INGRESS_FC_CTRL_EN(port)	BIT(port % 29)

/* Storm control: a leaky bucket per port for unicast, multicast and broadcast */
#define RTL930X_STORM_CTRL			0x8A60
#define RTL930X_STORM_CTRL_ADMIT_RTKPKT		BIT(1)
#define RTL930X_STORM_CTRL_ADMIT_BPDU		BIT(2)
#define RTL930X_STORM_CTRL_ADMIT_RMA		BIT(3)
#define RTL930X_STORM_LB_CTRL			0x8A64
#define RTL930X_STORM_LB_CTRL_TOKEN		GENMASK(15, 0)
/* one bit per port: the port's meters count bytes (16 kbit/s units), else packets */
#define RTL930X_STORM_PORT_MODE			0x8A6C
#define RTL930X_STORM_PORT_UC_CTRL(port)	(0x8A70 + ((port) * 8))
#define RTL930X_STORM_PORT_MC_CTRL(port)	(0x8B60 + ((port) * 8))
#define RTL930X_STORM_PORT_BC_CTRL(port)	(0x8C50 + ((port) * 8))
/* unicast and multicast: known and unknown destinations, else unknown ones only */
#define RTL930X_STORM_PORT_CTRL_ALL		BIT(25)
#define RTL930X_STORM_PORT_CTRL_EN		BIT(24)
#define RTL930X_STORM_PORT_CTRL_RATE		GENMASK(23, 0)
/* the second word of a meter: its bucket in bytes or packets */
#define RTL930X_STORM_PORT_BURST		GENMASK(15, 0)
/* one bit per port each: reset the bucket, and the meter dropped frames (stays set) */
#define RTL930X_STORM_PORT_UC_LB_RST		0x8B58
#define RTL930X_STORM_PORT_UC_EXCEED		0x8B5C
#define RTL930X_STORM_PORT_MC_LB_RST		0x8C48
#define RTL930X_STORM_PORT_MC_EXCEED		0x8C4C
#define RTL930X_STORM_PORT_BC_LB_RST		0x8D38
#define RTL930X_STORM_PORT_BC_EXCEED		0x8D3C
#define RTL930X_STORM_PORT_CTRL_DEFAULT		0x000fffff
#define RTL930X_STORM_PORT_BURST_DEFAULT	0xff

/* Parse the flow rule for the matching conditions */
static int otto_tc_parse_flow_rule(struct otto_dsa_priv *priv,
				   struct flow_rule *rule, struct rtl83xx_flow *flow)
{
	struct flow_dissector *dissector = rule->match.dissector;
	struct flow_match_control control;
	u64 supported_keys;

	dev_dbg(priv->dev, "parsing flower match keys\n");
	/* KEY_CONTROL and KEY_BASIC are needed for forming a meaningful key */
	if ((dissector->used_keys & BIT(FLOW_DISSECTOR_KEY_CONTROL)) == 0 ||
	    (dissector->used_keys & BIT(FLOW_DISSECTOR_KEY_BASIC)) == 0) {
		dev_err(priv->dev, "cannot form a TC key: used_keys = 0x%llx\n", dissector->used_keys);
		return -EOPNOTSUPP;
	}

	supported_keys = BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) |
			 BIT_ULL(FLOW_DISSECTOR_KEY_BASIC) |
			 BIT_ULL(FLOW_DISSECTOR_KEY_ETH_ADDRS) |
			 BIT_ULL(FLOW_DISSECTOR_KEY_VLAN) |
			 BIT_ULL(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
			 BIT_ULL(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
			 BIT_ULL(FLOW_DISSECTOR_KEY_PORTS);
	if (priv->r->pie_qos)
		supported_keys |= BIT_ULL(FLOW_DISSECTOR_KEY_IP);
	if (dissector->used_keys & ~supported_keys) {
		dev_err(priv->dev, "unsupported TC keys: used_keys = 0x%llx\n",
			dissector->used_keys & ~supported_keys);
		return -EOPNOTSUPP;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		dev_dbg(priv->dev, "match BASIC\n");
		flow_rule_match_basic(rule, &match);
		if (match.mask->n_proto) {
			if (match.mask->n_proto != htons(0xffff))
				return -EOPNOTSUPP;

			if (match.key->n_proto == htons(ETH_P_ARP)) {
				flow->rule.frame_type = 0;
			} else if (match.key->n_proto == htons(ETH_P_IP)) {
				flow->rule.frame_type = 2;
			} else if (match.key->n_proto == htons(ETH_P_IPV6)) {
				flow->rule.frame_type = 3;
			} else {
				flow->rule.frame_type = 1;
				flow->rule.ethertype = ntohs(match.key->n_proto);
				flow->rule.ethertype_m = ntohs(match.mask->n_proto);
			}
			flow->rule.frame_type_m = 3;
		}
		if (match.mask->ip_proto) {
			if (flow->rule.frame_type < 2 || match.mask->ip_proto != 0xff)
				return -EOPNOTSUPP;

			switch (match.key->ip_proto) {
			case IPPROTO_UDP:
				flow->rule.frame_type_l4 = 0;
				break;
			case IPPROTO_TCP:
				flow->rule.frame_type_l4 = 1;
				break;
			case IPPROTO_ICMP:
			case IPPROTO_ICMPV6:
				flow->rule.frame_type_l4 = 2;
				break;
			case IPPROTO_IGMP:
				flow->rule.frame_type_l4 = 3;
				break;
			default:
				/* any other protocol: the low byte of the TOS/protocol field */
				if (!priv->r->pie_qos)
					return -EOPNOTSUPP;
				flow->rule.tos_proto |= match.key->ip_proto;
				flow->rule.tos_proto_m |= 0xff;
				break;
			}
			if (!flow->rule.tos_proto_m)
				flow->rule.frame_type_l4_m = 7;
		}
	}

	/* the high byte of the TOS/protocol field: IPv4 TOS, IPv6 traffic class */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IP)) {
		struct flow_match_ip match;

		flow_rule_match_ip(rule, &match);
		if (match.mask->ttl || flow->rule.frame_type < 2)
			return -EOPNOTSUPP;
		flow->rule.tos_proto |= (u16)match.key->tos << 8;
		flow->rule.tos_proto_m |= (u16)match.mask->tos << 8;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		struct flow_match_eth_addrs match;

		dev_dbg(priv->dev, "match ETH_ADDR\n");
		flow_rule_match_eth_addrs(rule, &match);
		ether_addr_copy(flow->rule.dmac, match.key->dst);
		ether_addr_copy(flow->rule.dmac_m, match.mask->dst);
		ether_addr_copy(flow->rule.smac, match.key->src);
		ether_addr_copy(flow->rule.smac_m, match.mask->src);
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN)) {
		struct flow_match_vlan match;

		dev_dbg(priv->dev, "match VLAN\n");
		flow_rule_match_vlan(rule, &match);
		if ((match.mask->vlan_priority && !priv->r->pie_qos) || match.mask->vlan_dei)
			return -EOPNOTSUPP;
		/* flower puts the ethertype after the tag in BASIC too, which the frame
		 * type above matches already (the PIE looks past the tag)
		 */
		if (match.mask->vlan_eth_type &&
		    (!priv->r->pie_qos || match.mask->vlan_eth_type != htons(0xffff) ||
		     flow->rule.frame_type < 2 ||
		     match.key->vlan_eth_type != htons(flow->rule.frame_type == 2 ?
						       ETH_P_IP : ETH_P_IPV6)))
			return -EOPNOTSUPP;
		/* cls_flower sets a full vlan_tpid mask for every VLAN-ethertype
		 * rule; only reject a TPID the PIE cannot match on.
		 */
		if (match.mask->vlan_tpid &&
		    match.key->vlan_tpid != htons(ETH_P_8021Q))
			return -EOPNOTSUPP;
		flow->rule.itag = match.key->vlan_id;
		flow->rule.itag_m = match.mask->vlan_id;
		/* the PCP is bits 15:13 of the field; a frame without a tag would show the
		 * port's priority there, so the frame must carry one
		 */
		if (match.mask->vlan_priority) {
			flow->rule.itag |= (u16)match.key->vlan_priority << 13;
			flow->rule.itag_m |= (u16)match.mask->vlan_priority << 13;
			flow->rule.itag_exist = true;
			flow->rule.itag_exist_m = true;
		}
	}

	/* cls_flower keeps IPv4 and IPv6 addresses in one union, so an IPv4
	 * rule shows the IPv6 key in use too: the address type tells which
	 * one the rule holds, the key whether it matches on it at all.
	 */
	flow_rule_match_control(rule, &control);
	if (control.key->addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS &&
	    flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS)) {
		struct flow_match_ipv4_addrs match;

		dev_dbg(priv->dev, "match IPV4\n");
		flow_rule_match_ipv4_addrs(rule, &match);
		flow->rule.is_ipv6 = false;
		flow->rule.dip = match.key->dst;
		flow->rule.dip_m = match.mask->dst;
		flow->rule.sip = match.key->src;
		flow->rule.sip_m = match.mask->src;
	} else if (control.key->addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS &&
		   flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV6_ADDRS)) {
		struct flow_match_ipv6_addrs match;

		dev_dbg(priv->dev, "match IPV6\n");
		flow->rule.is_ipv6 = true;
		flow_rule_match_ipv6_addrs(rule, &match);
		flow->rule.dip6 = match.key->dst;
		flow->rule.dip6_m = match.mask->dst;
		flow->rule.sip6 = match.key->src;
		flow->rule.sip6_m = match.mask->src;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports match;

		dev_dbg(priv->dev, "match PORTS\n");
		flow_rule_match_ports(rule, &match);
		flow->rule.dport = match.key->dst;
		flow->rule.dport_m = match.mask->dst;
		flow->rule.sport = match.key->src;
		flow->rule.sport_m = match.mask->src;
	}

	/* TODO: ICMP */
	return 0;
}

static void otto_tc_flow_bypass_all(struct rtl83xx_flow *flow)
{
	flow->rule.bypass_sel = true;
	flow->rule.bypass_all = true;
	flow->rule.bypass_igr_stp = true;
	flow->rule.bypass_ibc_sc = true;
}

/* The actions of a classifying rule: one each of priority, remark of the IP header
 * and PCP of the egress tag, and nothing else, so that the rule can take blocks of
 * its own (see otto_pie_930x_block_fits()).
 */
static int otto_tc_validate_flow_actions(struct otto_dsa_priv *priv, struct flow_rule *rule,
					 bool *qos)
{
	const struct flow_action_entry *act;
	bool drop = false, fwd = false, accept = false;
	u64 marks = 0;
	int i, count = 0;

	flow_action_for_each(i, act, &rule->action) {
		count++;
		switch (act->id) {
		case FLOW_ACTION_DROP:
			drop = true;
			break;
		case FLOW_ACTION_ACCEPT:
			accept = true;
			break;
		case FLOW_ACTION_TRAP:
		case FLOW_ACTION_REDIRECT:
		case FLOW_ACTION_MIRRED:
			if (fwd)
				return -EOPNOTSUPP;
			fwd = true;
			break;
		case FLOW_ACTION_PRIORITY:
		case FLOW_ACTION_MANGLE:
		case FLOW_ACTION_VLAN_MANGLE:
			if (!priv->r->pie_qos || (marks & BIT_ULL(act->id)))
				return -EOPNOTSUPP;
			marks |= BIT_ULL(act->id);
			break;
		default:
			/* FLOW_ACTION_VLAN_PUSH / _POP map to the ivid/ovid PIE
			 * action fields via the translation in otto_tc_add_flow(),
			 * which predates this offload and has never been exercised
			 * through it. Keep them - and every other action - rejected
			 * until that path is reviewed.
			 */
			return -EOPNOTSUPP;
		}
	}

	if (!count || (drop && count != 1) || (accept && count != 1) || (marks && fwd))
		return -EOPNOTSUPP;

	*qos = !!marks;
	return 0;
}

/* pedit of the TOS byte (IPv4) or traffic class (IPv6) to a remark: of the DSCP
 * (ECN kept), of the precedence (the rest kept) or of the whole byte
 */
static int otto_tc_parse_remark(const struct flow_action_entry *act, struct rtl83xx_flow *flow)
{
	u32 mask = ntohl((__force __be32)act->mangle.mask);
	u32 val = ntohl((__force __be32)act->mangle.val);
	u32 changed = ~mask;
	int shift;

	if (act->mangle.offset != 0)
		return -EOPNOTSUPP;
	if (act->mangle.htype == FLOW_ACT_MANGLE_HDR_TYPE_IP4 && flow->rule.frame_type == 2)
		shift = 16;
	else if (act->mangle.htype == FLOW_ACT_MANGLE_HDR_TYPE_IP6 && flow->rule.frame_type == 3)
		shift = 20;
	else
		return -EOPNOTSUPP;
	if (changed & ~(0xffU << shift))
		return -EOPNOTSUPP;

	changed >>= shift;
	val = (val >> shift) & changed;
	switch (changed) {
	case 0xfc:
		flow->rule.rmk_act = 0;
		flow->rule.rmk_data = val >> 2;
		break;
	case 0xe0:
		flow->rule.rmk_act = 1;
		flow->rule.rmk_data = val >> 5;
		break;
	case 0xff:
		flow->rule.rmk_act = 2;
		flow->rule.rmk_data = val;
		break;
	default:
		return -EOPNOTSUPP;
	}
	flow->rule.rmk_sel = true;

	return 0;
}

static int otto_tc_parse_fwd(struct otto_dsa_priv *priv,
			     const struct flow_action_entry *act, struct rtl83xx_flow *flow)
{
	struct net_device *dev = act->dev;
	int port;

	port = rtl83xx_port_is_under(dev, priv);
	if (port < 0) {
		netdev_info(dev, "not a DSA port on this switch\n");
		return -EINVAL;
	}

	flow->rule.fwd_sel = true;
	flow->rule.fwd_data = port;
	dev_dbg(priv->dev, "redirect/mirror to port %d\n", port);
	otto_tc_flow_bypass_all(flow);

	return 0;
}

static int otto_tc_add_flow(struct otto_dsa_priv *priv, struct flow_cls_offload *f,
			    struct rtl83xx_flow *flow)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	const struct flow_action_entry *act;
	int i, err, port;

	dev_dbg(priv->dev, "adding flower rule\n");

	if (flow_rule_match_has_control_flags(rule, f->common.extack))
		return -EOPNOTSUPP;

	if (!flow_action_hw_stats_check(&rule->action, f->common.extack,
					FLOW_ACTION_HW_STATS_IMMEDIATE_BIT))
		return -EOPNOTSUPP;

	err = otto_tc_validate_flow_actions(priv, rule, &flow->rule.qos);
	if (err)
		return err;

	/* a rule of an ordered list drops or accepts, and an accept only means
	 * something in a list: it keeps the later entries of the list off the frame
	 */
	if (f->common.chain_index ?
	    (rule->action.entries[0].id != FLOW_ACTION_DROP &&
	     rule->action.entries[0].id != FLOW_ACTION_ACCEPT) :
	    rule->action.entries[0].id == FLOW_ACTION_ACCEPT)
		return -EOPNOTSUPP;

	err = otto_tc_parse_flow_rule(priv, rule, flow);
	if (err)
		return err;

	flow_action_for_each(i, act, &rule->action) {
		switch (act->id) {
		case FLOW_ACTION_PRIORITY:
			/* priority n is queue n (otto_qos_930x_prio2queue_matrix()) */
			if (act->priority >= MAX_PRIOS)
				return -EOPNOTSUPP;
			flow->rule.nopri_sel = true;
			flow->rule.nopri_data = act->priority;
			break;

		case FLOW_ACTION_MANGLE:
			err = otto_tc_parse_remark(act, flow);
			if (err)
				return err;
			break;

		case FLOW_ACTION_VLAN_MANGLE:
			/* the hardware sets only the PCP: the rule has to keep the VLAN it
			 * matches
			 */
			if (act->vlan.proto != htons(ETH_P_8021Q) ||
			    (flow->rule.itag_m & VLAN_VID_MASK) != VLAN_VID_MASK ||
			    (flow->rule.itag & VLAN_VID_MASK) != act->vlan.vid)
				return -EOPNOTSUPP;
			flow->rule.ipri_sel = true;
			flow->rule.ipri_data = act->vlan.prio;
			break;

		case FLOW_ACTION_DROP:
			dev_dbg(priv->dev, "action DROP\n");
			flow->rule.drop = true;
			otto_tc_flow_bypass_all(flow);
			return 0;

		case FLOW_ACTION_TRAP:
			dev_dbg(priv->dev, "action TRAP\n");
			flow->rule.fwd_sel = true;
			flow->rule.fwd_data = priv->r->cpu_port;
			flow->rule.fwd_act = PIE_ACT_REDIRECT_TO_PORT;
			otto_tc_flow_bypass_all(flow);
			break;

		case FLOW_ACTION_ACCEPT:
			/* an entry that sets nothing: it only takes the frame */
			break;

		case FLOW_ACTION_ADD:
			dev_err(priv->dev, "unsupported action: ADD\n");
			return -EOPNOTSUPP;

		case FLOW_ACTION_VLAN_PUSH:
			dev_dbg(priv->dev, "action VLAN_PUSH\n");
/*			TODO: act->vlan.proto */
			flow->rule.ivid_act = PIE_ACT_VID_ASSIGN;
			flow->rule.ivid_sel = true;
			flow->rule.ivid_data = htons(act->vlan.vid);
			flow->rule.ovid_act = PIE_ACT_VID_ASSIGN;
			flow->rule.ovid_sel = true;
			flow->rule.ovid_data = htons(act->vlan.vid);
			flow->rule.fwd_mod_to_cpu = true;
			break;

		case FLOW_ACTION_VLAN_POP:
			dev_dbg(priv->dev, "action VLAN_POP\n");
			flow->rule.ivid_act = PIE_ACT_VID_ASSIGN;
			flow->rule.ivid_data = 0;
			flow->rule.ivid_sel = true;
			flow->rule.ovid_act = PIE_ACT_VID_ASSIGN;
			flow->rule.ovid_data = 0;
			flow->rule.ovid_sel = true;
			flow->rule.fwd_mod_to_cpu = true;
			break;

		case FLOW_ACTION_CSUM:
			dev_err(priv->dev, "unsupported action: CSUM\n");
			return -EOPNOTSUPP;

		case FLOW_ACTION_REDIRECT:
			dev_dbg(priv->dev, "action REDIRECT\n");
			err = otto_tc_parse_fwd(priv, act, flow);
			if (err)
				return err;
			flow->rule.fwd_act = PIE_ACT_REDIRECT_TO_PORT;
			break;

		case FLOW_ACTION_MIRRED:
			dev_dbg(priv->dev, "action MIRRED\n");
			if (!priv->r->pie_mirror_group) {
				err = otto_tc_parse_fwd(priv, act, flow);
				if (err)
					return err;
				flow->rule.fwd_act = PIE_ACT_COPY_TO_PORT;
				break;
			}
			port = rtl83xx_port_is_under(act->dev, priv);
			if (port < 0) {
				netdev_info(act->dev, "not a DSA port on this switch\n");
				return -EINVAL;
			}
			/* A copy through the forwarding action would take over the
			 * forwarding decision of the L3 rules in later blocks.
			 */
			err = otto_mirror_group_get(priv, port);
			if (err < 0) {
				if (err == -ENOSPC)
					NL_SET_ERR_MSG_MOD(f->common.extack,
							   "all four mirror groups are in use");
				return err;
			}
			flow->rule.mir_sel = true;
			flow->rule.mir_data = err;
			break;

		default:
			dev_err(priv->dev, "unsupported action: %d\n", act->id);
			return -EOPNOTSUPP;
		}
	}

	return 0;
}

static const struct rhashtable_params tc_ht_params = {
	.head_offset = offsetof(struct rtl83xx_flow, node),
	.key_offset = offsetof(struct rtl83xx_flow, cookie),
	.key_len = sizeof(((struct rtl83xx_flow *)0)->cookie),
	.automatic_shrinking = true,
};

#define OTTO_TC_RED_POLL_INTERVAL	msecs_to_jiffies(50)

static void otto_tc_red_poll(struct work_struct *work)
{
	struct otto_dsa_priv *priv = container_of(to_delayed_work(work),
						  struct otto_dsa_priv, red_work);

	guard(mutex)(&priv->reg_mutex);

	for (int port = 0; port < priv->r->cpu_port; port++)
		priv->r->red_drops_update(priv, port);

	if (priv->red_ports)
		queue_delayed_work(priv->wq, &priv->red_work, OTTO_TC_RED_POLL_INTERVAL);
}

int otto_tc_init(struct otto_dsa_priv *priv)
{
	int err;

	if (priv->tc_initialized)
		return 0;

	err = rhashtable_init(&priv->tc_ht, &tc_ht_params);
	if (err)
		return err;

	mutex_init(&priv->tc_flow_lock);
	INIT_LIST_HEAD(&priv->tc_lists);
	INIT_DELAYED_WORK(&priv->red_work, otto_tc_red_poll);
	priv->tc_initialized = true;

	return 0;
}

/* A rule of an ordered list (a chain other than 0, skip_sw) on any number of ports
 * is one PIE entry: the ports it is on are its source port mask. A frame matches
 * when the mask bits of the ports the rule is not on are 0 - as for a frame from
 * a port the rule is on, whose port is the only bit it sets. The entries move
 * when another one goes in before them, so they count no packets.
 */
static u64 otto_tc_list_spm_m(struct otto_dsa_priv *priv, u64 ports)
{
	return GENMASK_ULL(priv->r->cpu_port, 0) & ~ports;
}

/* the same rule but for what the entry sets for itself */
static bool otto_tc_list_same(const struct pie_rule *a, const struct pie_rule *b)
{
	struct pie_rule x;

	memcpy(&x, b, sizeof(x));
	x.id = a->id;
	x.valid = a->valid;
	x.tid = a->tid;
	x.tid_m = a->tid_m;
	x.spm = a->spm;
	x.spm_m = a->spm_m;
	x.spn = a->spn;
	x.spn_m = a->spn_m;
	x.packet_cntr = a->packet_cntr;
	x.last_packet_cnt = a->last_packet_cnt;
	x.log_sel = a->log_sel;
	x.log_data = a->log_data;

	return !memcmp(a, &x, sizeof(x));
}

static int otto_tc_list_rewrite(struct otto_dsa_priv *priv, struct otto_tc_list *l)
{
	l->rule.spm_m = otto_tc_list_spm_m(priv, l->ports);
	guard(mutex)(&priv->pie_mutex);

	return priv->r->pie_rule_write(priv, l->rule.id, &l->rule);
}

static int otto_tc_list_get(struct otto_dsa_priv *priv, struct rtl83xx_flow *flow,
			    struct flow_cls_offload *f, int port)
{
	struct otto_tc_list *l;
	int err;

	if (!priv->r->pie_lists || !f->common.skip_sw || flow->rule.is_egress ||
	    port < 0 || port >= ARRAY_SIZE(l->port_refs))
		return -EOPNOTSUPP;

	flow->rule.list = f->common.chain_index;
	flow->rule.list_prio = f->common.prio;
	flow->port = port;

	list_for_each_entry(l, &priv->tc_lists, node) {
		if (l->rule.list != flow->rule.list || l->rule.list_prio != flow->rule.list_prio)
			continue;
		if (!otto_tc_list_same(&l->rule, &flow->rule)) {
			NL_SET_ERR_MSG_MOD(f->common.extack,
					   "the list has another rule at this prio");
			return -EOPNOTSUPP;
		}
		if (!l->port_refs[port]) {
			l->ports |= BIT_ULL(port);
			err = otto_tc_list_rewrite(priv, l);
			if (err) {
				l->ports &= ~BIT_ULL(port);
				otto_tc_list_rewrite(priv, l);
				return err;
			}
		}
		l->port_refs[port]++;
		flow->list = l;
		return 0;
	}

	l = kzalloc(sizeof(*l), GFP_KERNEL);
	if (!l)
		return -ENOMEM;
	memcpy(&l->rule, &flow->rule, sizeof(l->rule));
	l->rule.spn = 0;
	l->rule.spn_m = 0;
	l->rule.spm = 0;
	l->ports = BIT_ULL(port);
	l->port_refs[port] = 1;
	l->rule.spm_m = otto_tc_list_spm_m(priv, l->ports);
	l->rule.log_sel = false;
	l->rule.packet_cntr = -1;

	err = priv->r->pie_rule_add(priv, &l->rule);
	if (err) {
		kfree(l);
		return err;
	}
	list_add_tail(&l->node, &priv->tc_lists);
	flow->list = l;

	return 0;
}

static void otto_tc_list_put(struct otto_dsa_priv *priv, struct rtl83xx_flow *flow)
{
	struct otto_tc_list *l = flow->list;

	flow->list = NULL;
	if (--l->port_refs[flow->port])
		return;

	l->ports &= ~BIT_ULL(flow->port);
	if (l->ports) {
		if (otto_tc_list_rewrite(priv, l))
			dev_err(priv->dev, "port %d stays on a list rule\n", flow->port);
		return;
	}

	priv->r->pie_rule_rm(priv, &l->rule);
	list_del(&l->node);
	kfree(l);
}

/* the hardware side of a flow on its way out */
static void otto_tc_flow_rm(struct otto_dsa_priv *priv, struct rtl83xx_flow *flow)
{
	if (flow->list)
		otto_tc_list_put(priv, flow);
	else
		priv->r->pie_rule_rm(priv, &flow->rule);
}

/* Zero a PIE rule's LOG-table packet counter */
static void otto_tc_packet_cntr_clear(struct otto_dsa_priv *priv, int counter)
{
	if (counter < 0 || !priv->r->packet_cntr_clear)
		return;

	mutex_lock(&priv->reg_mutex);
	priv->r->packet_cntr_clear(priv, counter);
	mutex_unlock(&priv->reg_mutex);
}

/* A flow's counter on its way out: zeroed, and handed back to the allocator
 * where it came from there. On RTL930x the counter id is the PIE rule id
 * itself: the rule owns it and pie_rule_rm() releases it.
 */
static void otto_tc_packet_cntr_put(struct otto_dsa_priv *priv, int counter)
{
	otto_tc_packet_cntr_clear(priv, counter);
	if (!priv->r->pie_rule_id_is_log_counter)
		otto_stats_packet_cntr_free(priv, counter);
}

static void otto_tc_flow_free(void *ptr, void *arg)
{
	struct rtl83xx_flow *flow = ptr;
	struct otto_dsa_priv *priv = arg;

	otto_tc_flow_rm(priv, flow);
	otto_tc_packet_cntr_put(priv, flow->rule.packet_cntr);
	if (flow->rule.mir_sel)
		otto_mirror_group_put(priv, flow->rule.mir_data);

	/* Readers may still hold an RCU-protected reference after the
	 * object has been removed from the hash table.
	 */
	kfree_rcu(flow, rcu_head);
}

void otto_tc_cleanup(struct otto_dsa_priv *priv)
{
	if (!priv->tc_initialized)
		return;

	cancel_delayed_work_sync(&priv->red_work);

	/* Hold tc_flow_lock like the add/del/stats callbacks do: any
	 * callback that slipped in before teardown must finish before the
	 * table and rules are torn down, otherwise it can walk a half-freed
	 * flow or run pie_rule_rm() against a rule this path already removed.
	 */
	mutex_lock(&priv->tc_flow_lock);
	rhashtable_free_and_destroy(&priv->tc_ht, otto_tc_flow_free, priv);
	priv->tc_initialized = false;
	mutex_unlock(&priv->tc_flow_lock);

	rcu_barrier();
	mutex_destroy(&priv->tc_flow_lock);
}

static int otto_tc_configure_flower(struct otto_dsa_priv *priv,
				    struct flow_cls_offload *f, int ingress_port)
{
	struct rtl83xx_flow *flow;
	int err = 0;

	dev_dbg(priv->dev, "configuring flower rule\n");

	if (!priv->r->packet_cntr_read || !priv->r->packet_cntr_clear)
		return -EOPNOTSUPP;

	dev_dbg(priv->dev, "cookie %08lx\n", f->cookie);

	mutex_lock(&priv->tc_flow_lock);

	/* otto_tc_cleanup() clears this under the lock before it destroys
	 * tc_ht; a callback that was parked on the lock must bail rather than
	 * walk the freed table.
	 */
	if (!priv->tc_initialized) {
		err = -ENODEV;
		goto out_unlock;
	}

	flow = rhashtable_lookup_fast(&priv->tc_ht, &f->cookie, tc_ht_params);
	if (flow) {
		dev_dbg(priv->dev, "cookie already offloaded\n");
		err = -EEXIST;
		goto out_unlock;
	}
	dev_dbg(priv->dev, "new flow\n");

	flow = kzalloc(sizeof(*flow), GFP_KERNEL);
	if (!flow) {
		err = -ENOMEM;
		goto out_unlock;
	}

	flow->cookie = f->cookie;
	flow->priv = priv;
	/* kzalloc() leaves this at 0, a valid counter id; -1 means "none". */
	flow->rule.packet_cntr = -1;

	err = rhashtable_insert_fast(&priv->tc_ht, &flow->node, tc_ht_params);
	if (err) {
		dev_err(priv->dev, "could not insert new rule\n");
		goto out_free;
	}

	err = otto_tc_add_flow(priv, f, flow);
	if (err)
		goto out_remove;

	if (f->common.chain_index) {
		err = otto_tc_list_get(priv, flow, f, ingress_port);
		if (err)
			goto out_remove;
		mutex_unlock(&priv->tc_flow_lock);
		return 0;
	}

	flow->rule.spn = ingress_port;
	flow->rule.spn_m = 0x7f;

	/* Where the PIE rule ID is also the LOG table counter ID (RTL930x), the
	 * counter is implied by the rule and only known once pie_rule_add() has
	 * assigned the ID. That range is kept out of otto_stats_packet_cntr_alloc(),
	 * so the implied LOG entry cannot alias an L3 route PIE rule's counter.
	 * Elsewhere the rule logs into a counter of its own from the allocator.
	 */
	flow->rule.log_sel = true;
	if (!priv->r->pie_rule_id_is_log_counter) {
		flow->rule.packet_cntr = otto_stats_packet_cntr_alloc(priv);
		if (flow->rule.packet_cntr < 0) {
			err = -ENOSPC;
			goto out_remove;
		}
		flow->rule.log_data = flow->rule.packet_cntr;
	}

	err = priv->r->pie_rule_add(priv, &flow->rule);
	if (err)
		goto out_remove;

	if (priv->r->pie_rule_id_is_log_counter)
		flow->rule.packet_cntr = flow->rule.id;
	dev_dbg(priv->dev, "using PIE rule counter %d\n", flow->rule.packet_cntr);
	otto_tc_packet_cntr_clear(priv, flow->rule.packet_cntr);

	mutex_unlock(&priv->tc_flow_lock);
	return 0;

out_remove:
	rhashtable_remove_fast(&priv->tc_ht, &flow->node, tc_ht_params);
	otto_tc_packet_cntr_put(priv, flow->rule.packet_cntr);
	if (flow->rule.mir_sel)
		otto_mirror_group_put(priv, flow->rule.mir_data);
	/* published in tc_ht above; a concurrent reader may still hold a ref */
	kfree_rcu(flow, rcu_head);
	goto out_err;
out_free:
	kfree(flow);
out_err:
	dev_err(priv->dev, "flower rule setup failed: %d\n", err);
out_unlock:
	mutex_unlock(&priv->tc_flow_lock);

	return err;
}

static int otto_tc_delete_flower(struct otto_dsa_priv *priv,
				 struct flow_cls_offload *cls_flower)
{
	struct rtl83xx_flow *flow;
	int err;

	dev_dbg(priv->dev, "deleting flower rule\n");

	mutex_lock(&priv->tc_flow_lock);

	/* see otto_tc_configure_flower(): bail if teardown already ran */
	if (!priv->tc_initialized) {
		err = -ENODEV;
		goto out_unlock;
	}

	flow = rhashtable_lookup_fast(&priv->tc_ht, &cls_flower->cookie, tc_ht_params);
	if (!flow) {
		err = -ENOENT;
		goto out_unlock;
	}

	err = rhashtable_remove_fast(&priv->tc_ht, &flow->node, tc_ht_params);
	if (err)
		goto out_unlock;

	otto_tc_flow_rm(priv, flow);
	otto_tc_packet_cntr_put(priv, flow->rule.packet_cntr);
	if (flow->rule.mir_sel)
		otto_mirror_group_put(priv, flow->rule.mir_data);

	kfree_rcu(flow, rcu_head);

out_unlock:
	mutex_unlock(&priv->tc_flow_lock);

	return err;
}

static int otto_tc_stats_flower(struct otto_dsa_priv *priv,
				struct flow_cls_offload *cls_flower)
{
	struct rtl83xx_flow *flow;
	unsigned long lastused = 0;
	u32 total_packets, new_packets = 0;
	int err = 0;

	dev_dbg(priv->dev, "reading flower rule stats\n");

	mutex_lock(&priv->tc_flow_lock);

	/* see otto_tc_configure_flower(): bail if teardown already ran */
	if (!priv->tc_initialized) {
		err = -ENODEV;
		goto out_unlock;
	}

	flow = rhashtable_lookup_fast(&priv->tc_ht, &cls_flower->cookie, tc_ht_params);
	if (!flow) {
		err = -ENOENT;
		goto out_unlock;
	}

	/* tc_flow_lock keeps the flow alive for the duration of the sleeping
	 * counter read, so it is safe to dereference it here.
	 */
	if (flow->rule.packet_cntr >= 0) {
		mutex_lock(&priv->reg_mutex);
		total_packets = priv->r->packet_cntr_read(priv, flow->rule.packet_cntr);
		mutex_unlock(&priv->reg_mutex);
		dev_dbg(priv->dev, "total packets: %u\n", total_packets);

		new_packets = total_packets - flow->rule.last_packet_cnt;
		flow->rule.last_packet_cnt = total_packets;
	}

	/* We have no byte counter, report packets only */
	flow_stats_update(&cls_flower->stats, 0, new_packets, 0, lastused,
			  FLOW_ACTION_HW_STATS_IMMEDIATE);

out_unlock:
	mutex_unlock(&priv->tc_flow_lock);

	return err;
}

static int otto_tc_pie_cls_flower_add(struct otto_dsa_priv *priv, int port,
				      struct flow_cls_offload *cls, bool ingress)
{
	if (!ingress || !priv->r->pie_cls_flower)
		return -EOPNOTSUPP;

	/* No goto chain is offloaded, so in hardware a rule of another chain sees
	 * frames that never reach it in software: such a rule is an entry of an
	 * ordered list (otto_tc_list_get()), in hardware only.
	 */
	if (cls->common.chain_index && (!priv->r->pie_lists || !cls->common.skip_sw)) {
		NL_SET_ERR_MSG_MOD(cls->common.extack,
				   "only chain 0 is offloaded, other chains as skip_sw lists");
		return -EOPNOTSUPP;
	}

	return otto_tc_configure_flower(priv, cls, port);
}

static int otto_tc_pie_cls_flower_del(struct otto_dsa_priv *priv,
				      struct flow_cls_offload *cls, bool ingress)
{
	if (!ingress || !priv->r->pie_cls_flower)
		return -ENOENT;

	return otto_tc_delete_flower(priv, cls);
}

static int otto_tc_pie_cls_flower_stats(struct otto_dsa_priv *priv,
					struct flow_cls_offload *cls, bool ingress)
{
	if (!ingress || !priv->r->pie_cls_flower)
		return -ENOENT;

	return otto_tc_stats_flower(priv, cls);
}

static const struct flow_action_entry *
otto_tc_rate_policy_extract(struct flow_cls_offload *cls)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls);

	/* only simple rules with a single action are supported */
	if (!flow_offload_has_one_action(&rule->action))
		return NULL;

	/* Anything that is not a policer is offloaded to PIE. Bail out before
	 * flow_action_basic_hw_stats_check() so it does not stamp a "HW stats
	 * type unsupported" extack onto a rule the PIE path accepts.
	 */
	if (rule->action.entries[0].id != FLOW_ACTION_POLICE)
		return NULL;

	if (!flow_action_basic_hw_stats_check(&rule->action, cls->common.extack))
		return NULL;

	return &rule->action.entries[0];
}

/* No match on the protocol or on anything the basic and control keys carry */
static bool otto_tc_flower_any_proto(struct flow_cls_offload *cls)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls);
	struct flow_match_control control;
	struct flow_match_basic basic;

	if (cls->common.chain_index || cls->common.protocol != htons(ETH_P_ALL))
		return false;

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		flow_rule_match_basic(rule, &basic);
		if (basic.mask->n_proto || basic.mask->ip_proto)
			return false;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL)) {
		flow_rule_match_control(rule, &control);
		if (control.mask->addr_type || control.mask->flags)
			return false;
	}

	return true;
}

static bool otto_tc_flower_matches_all(struct flow_cls_offload *cls)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls);

	if (rule->match.dissector->used_keys &
	    ~(BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) | BIT_ULL(FLOW_DISSECTOR_KEY_BASIC)))
		return false;

	return otto_tc_flower_any_proto(cls);
}

/* A police action on all broadcast, multicast or unicast frames is the storm control of the
 * port, with one meter for each of the three, by the destination address:
 *
 *   dst_mac ff:ff:ff:ff:ff:ff                         broadcast
 *   dst_mac 01:00:00:00:00:00/01:00:00:00:00:00       multicast, broadcast not counted
 *   dst_mac 00:00:00:00:00:00/01:00:00:00:00:00       unicast
 *
 * With "l2_miss 1" the unicast and multicast meters see only the frames the switch floods for
 * lack of a forwarding entry (unknown unicast, unregistered multicast). Returns the meter, or -1
 * when the rule is something else.
 */
static int otto_tc_storm_match(struct flow_cls_offload *cls, bool *unknown_only)
{
	static const u8 group_bit[ETH_ALEN] = { 0x01 };
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls);
	struct flow_match_eth_addrs addrs;
	struct flow_match_meta meta;
	int type;

	if (rule->match.dissector->used_keys &
	    ~(BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) | BIT_ULL(FLOW_DISSECTOR_KEY_BASIC) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_ETH_ADDRS) | BIT_ULL(FLOW_DISSECTOR_KEY_META)))
		return -1;

	if (!otto_tc_flower_any_proto(cls) || !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS))
		return -1;

	flow_rule_match_eth_addrs(rule, &addrs);
	if (!is_zero_ether_addr(addrs.mask->src))
		return -1;

	if (is_broadcast_ether_addr(addrs.mask->dst)) {
		if (!is_broadcast_ether_addr(addrs.key->dst))
			return -1;
		type = RTLDSA_STORM_BC;
	} else if (ether_addr_equal(addrs.mask->dst, group_bit)) {
		type = is_multicast_ether_addr(addrs.key->dst) ? RTLDSA_STORM_MC : RTLDSA_STORM_UC;
	} else {
		return -1;
	}

	*unknown_only = false;
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_META)) {
		flow_rule_match_meta(rule, &meta);
		if (meta.mask->ingress_ifindex || meta.mask->ingress_iftype)
			return -1;
		/* there is no meter for the known destinations alone */
		if (meta.mask->l2_miss && !meta.key->l2_miss)
			return -1;
		/* broadcast has no forwarding entry, so it is all unknown anyway */
		*unknown_only = meta.mask->l2_miss && type != RTLDSA_STORM_BC;
	}

	return type;
}

static int otto_tc_storm_add(struct otto_dsa_priv *priv, int port, struct flow_cls_offload *cls,
			     const struct flow_action_entry *act, int type, bool unknown_only)
{
	static const char * const names[RTLDSA_STORM_NUM] = {
		[RTLDSA_STORM_UC] = "unicast",
		[RTLDSA_STORM_MC] = "multicast",
		[RTLDSA_STORM_BC] = "broadcast",
	};
	struct netlink_ext_ack *extack = cls->common.extack;
	struct rtldsa_port *p = &priv->ports[port];
	struct rtldsa_storm_cfg cfg = {
		.unknown_only = unknown_only,
	};
	int i, ret;

	if (!priv->r->port_storm_set) {
		NL_SET_ERR_MSG_MOD(extack, "this switch has no storm control");
		return -EOPNOTSUPP;
	}

	if (act->police.exceed.act_id != FLOW_ACTION_DROP ||
	    act->police.notexceed.act_id != FLOW_ACTION_ACCEPT) {
		NL_SET_ERR_MSG_MOD(extack, "storm control drops what exceeds: conform-exceed drop/ok");
		return -EOPNOTSUPP;
	}

	if (act->police.peakrate_bytes_ps || act->police.avrate || act->police.overhead) {
		NL_SET_ERR_MSG_MOD(extack, "storm control has a rate and a burst only");
		return -EOPNOTSUPP;
	}

	cfg.pps = act->police.rate_pkt_ps > 0;
	cfg.rate = cfg.pps ? act->police.rate_pkt_ps : act->police.rate_bytes_ps;
	cfg.burst = cfg.pps ? act->police.burst_pkt : act->police.burst;
	if (!cfg.rate) {
		NL_SET_ERR_MSG_MOD(extack, "storm control needs a rate");
		return -EOPNOTSUPP;
	}

	mutex_lock(&priv->reg_mutex);

	if (p->storm[type]) {
		NL_SET_ERR_MSG_FMT_MOD(extack, "the port's %s storm control is in use", names[type]);
		ret = -EBUSY;
		goto unlock;
	}

	for (i = 0; i < RTLDSA_STORM_NUM; i++) {
		if (p->storm[i] && p->storm_pps != cfg.pps) {
			NL_SET_ERR_MSG_MOD(extack,
					   "a port's storm controls all count packets or all count bytes");
			ret = -EOPNOTSUPP;
			goto unlock;
		}
	}

	ret = priv->r->port_storm_set(priv, port, type, &cfg);
	if (ret)
		goto unlock;

	p->storm[type] = cls->cookie;
	p->storm_pps = cfg.pps;

unlock:
	mutex_unlock(&priv->reg_mutex);

	return ret;
}

static int otto_tc_storm_del(struct otto_dsa_priv *priv, int port, struct flow_cls_offload *cls)
{
	struct rtldsa_port *p = &priv->ports[port];
	int type, ret = -ENOENT;

	mutex_lock(&priv->reg_mutex);

	for (type = 0; type < RTLDSA_STORM_NUM; type++) {
		if (!priv->r->port_storm_set || p->storm[type] != cls->cookie)
			continue;

		p->storm[type] = 0;
		ret = priv->r->port_storm_set(priv, port, type, NULL);
		break;
	}

	mutex_unlock(&priv->reg_mutex);

	return ret;
}

/* The chip only flags that a meter dropped frames, it does not count them: each time the flag is
 * found set (and cleared), the rule's drop count grows by one. So "dropped" counts the reads of the
 * statistics in which the meter had dropped something since the read before.
 */
static int otto_tc_storm_stats(struct otto_dsa_priv *priv, int port, struct flow_cls_offload *cls)
{
	struct rtldsa_port *p = &priv->ports[port];
	int type;

	guard(mutex)(&priv->reg_mutex);

	for (type = 0; type < RTLDSA_STORM_NUM; type++) {
		if (p->storm[type] != cls->cookie)
			continue;

		if (priv->r->port_storm_exceeded && priv->r->port_storm_exceeded(priv, port, type))
			flow_stats_update(&cls->stats, 0, 0, 1, jiffies, FLOW_ACTION_HW_STATS_IMMEDIATE);

		return 0;
	}

	return -ENOENT;
}

static bool otto_tc_port_rate_police_validate(const struct flow_action_entry *act)
{
	if (!act)
		return false;

	/* only allow action which just limit rate with by dropping packets */
	if (act->id != FLOW_ACTION_POLICE)
		return false;

	if (act->police.rate_pkt_ps > 0)
		return false;

	if (act->police.exceed.act_id != FLOW_ACTION_DROP)
		return false;

	if (act->police.notexceed.act_id != FLOW_ACTION_ACCEPT)
		return false;

	return true;
}

int otto_tc_930x_port_rate_police_add(struct dsa_switch *ds, int port,
				      const struct flow_action_entry *act,
				      bool ingress)
{
	struct otto_dsa_priv *priv = ds->priv;
	u32 burst;
	u64 rate;
	u32 addr;
	int err;

	/* rate has unit 16000 bit */
	rate = div_u64(act->police.rate_bytes_ps, 2000);
	rate = min_t(u64, rate, RTL93XX_BANDWIDTH_CTRL_RATE_MAX);
	rate |= RTL93XX_BANDWIDTH_CTRL_ENABLE;

	if (ingress)
		addr = RTL930X_BANDWIDTH_CTRL_INGRESS(port);
	else
		addr = RTL930X_BANDWIDTH_CTRL_EGRESS(port);

	if (ingress) {
		burst = min_t(u32, act->police.burst, RTL930X_BANDWIDTH_CTRL_INGRESS_BURST_MAX);

		/* the linux kernel only provides a single burst value. But the
		 * realtek HW needs two. And to get flow control correctly
		 * working, the realtek default ratio of 1:2 seems to work
		 * reasonable well
		 */
		err = regmap_write(priv->map, RTL930X_BANDWIDTH_CTRL_INGRESS_BURST_HIGH_ON(port),
				   burst);
		if (err)
			return err;
		err = regmap_write(priv->map, RTL930X_BANDWIDTH_CTRL_INGRESS_BURST_HIGH_OFF(port),
				   burst / 2);
		if (err)
			return err;

		/* Enable ingress bandwidth flow control to improve TCP throughput and avoid
		 * the drops behavior of the RTL930x ingress rate limiter which seem to not
		 * play well with any congestion control algorithm
		 */
		err = regmap_write_bits(priv->map, RTL930X_INGRESS_FC_CTRL(port),
					RTL930X_INGRESS_FC_CTRL_EN(port),
					RTL930X_INGRESS_FC_CTRL_EN(port));
		if (err)
			return err;
	} else {
		/* the bucket is 16 bit wide and has to hold the burst and one frame */
		burst = min_t(u32, act->police.burst, U16_MAX - priv->r->max_frame);

		err = regmap_write(priv->map, addr + 4, burst);
		if (err)
			return err;
	}

	return regmap_write(priv->map, addr, rate);
}

int otto_tc_930x_port_rate_police_del(struct dsa_switch *ds, int port,
				      struct flow_cls_offload *cls,
				      bool ingress)
{
	struct otto_dsa_priv *priv = ds->priv;
	u32 addr;
	int err;

	if (ingress)
		addr = RTL930X_BANDWIDTH_CTRL_INGRESS(port);
	else
		addr = RTL930X_BANDWIDTH_CTRL_EGRESS(port);

	err = regmap_write_bits(priv->map, addr, RTL93XX_BANDWIDTH_CTRL_ENABLE, 0);
	if (err)
		return err;

	if (ingress)
		return regmap_write_bits(priv->map, RTL930X_INGRESS_FC_CTRL(port),
					 RTL930X_INGRESS_FC_CTRL_EN(port), 0);

	return 0;
}

/* A queue below 0 is the shaper of the whole port and a rate of 0 switches the shaper off */
int otto_tc_930x_egress_shaper_set(struct otto_dsa_priv *priv, int port, int queue,
				   u64 rate_bytes_ps, u32 burst)
{
	u64 rate = div_u64(rate_bytes_ps, 2000);
	u32 addr, lb_ctrl;

	if (queue < 0)
		addr = RTL930X_BANDWIDTH_CTRL_EGRESS(port);
	else if (port < 24)
		addr = RTL930X_BANDWIDTH_CTRL_QUEUE_SET0(port, queue);
	else
		addr = RTL930X_BANDWIDTH_CTRL_QUEUE_SET1(port, queue);

	if (!rate_bytes_ps)
		return regmap_clear_bits(priv->map, addr, RTL93XX_BANDWIDTH_CTRL_ENABLE);

	/* the bucket is 16 bit wide and has to hold the burst and one frame, and the burst
	 * at least three of the tokens the bucket is refilled with
	 */
	regmap_read(priv->map, RTL930X_EGBW_LB_CTRL, &lb_ctrl);
	burst = min_t(u32, burst, U16_MAX - priv->r->max_frame);
	if (!rate || burst < 3 * FIELD_GET(RTL930X_EGBW_LB_CTRL_TOKEN, lb_ctrl))
		return -EINVAL;

	rate = min_t(u64, rate, RTL93XX_BANDWIDTH_CTRL_RATE_MAX);

	regmap_write(priv->map, addr + 4, burst);
	regmap_write(priv->map, addr, rate | RTL93XX_BANDWIDTH_CTRL_ENABLE);

	return 0;
}

static const u32 rtl930x_storm_exceed[RTLDSA_STORM_NUM] = {
	[RTLDSA_STORM_UC] = RTL930X_STORM_PORT_UC_EXCEED,
	[RTLDSA_STORM_MC] = RTL930X_STORM_PORT_MC_EXCEED,
	[RTLDSA_STORM_BC] = RTL930X_STORM_PORT_BC_EXCEED,
};

static const u32 rtl930x_storm_lb_rst[RTLDSA_STORM_NUM] = {
	[RTLDSA_STORM_UC] = RTL930X_STORM_PORT_UC_LB_RST,
	[RTLDSA_STORM_MC] = RTL930X_STORM_PORT_MC_LB_RST,
	[RTLDSA_STORM_BC] = RTL930X_STORM_PORT_BC_LB_RST,
};

/* Did the meter drop frames since the last call? Clears the flag. */
bool otto_tc_930x_port_storm_exceeded(struct otto_dsa_priv *priv, int port,
				      enum rtldsa_storm type)
{
	u32 flags;

	if (regmap_read(priv->map, rtl930x_storm_exceed[type], &flags) || !(flags & BIT(port)))
		return false;

	/* write one to clear; the vendor SDK resets the bucket instead */
	regmap_write(priv->map, rtl930x_storm_exceed[type], BIT(port));
	regmap_read(priv->map, rtl930x_storm_exceed[type], &flags);
	if (flags & BIT(port))
		regmap_write(priv->map, rtl930x_storm_lb_rst[type], BIT(port));

	return true;
}

int otto_tc_930x_port_storm_set(struct otto_dsa_priv *priv, int port, enum rtldsa_storm type,
				const struct rtldsa_storm_cfg *cfg)
{
	static const u32 ctrl_base[RTLDSA_STORM_NUM] = {
		[RTLDSA_STORM_UC] = RTL930X_STORM_PORT_UC_CTRL(0),
		[RTLDSA_STORM_MC] = RTL930X_STORM_PORT_MC_CTRL(0),
		[RTLDSA_STORM_BC] = RTL930X_STORM_PORT_BC_CTRL(0),
	};
	u32 addr = ctrl_base[type] + port * 8;
	u32 ctrl, burst, lb_ctrl;
	u64 rate;
	int i;

	if (!cfg) {
		regmap_write(priv->map, addr, RTL930X_STORM_PORT_CTRL_DEFAULT);
		regmap_write(priv->map, addr + 4, RTL930X_STORM_PORT_BURST_DEFAULT);

		/* back to the reset default once the port's last meter is off */
		for (i = 0; i < RTLDSA_STORM_NUM; i++)
			if (priv->ports[port].storm[i])
				return 0;

		return regmap_clear_bits(priv->map, RTL930X_STORM_PORT_MODE, BIT(port));
	}

	if (cfg->pps) {
		rate = cfg->rate;
		burst = clamp_t(u64, cfg->burst, 1, U16_MAX);
	} else {
		/* 16 kbit/s units; the bucket holds at least three of the tokens it is refilled
		 * with, as for the egress shaper
		 */
		regmap_read(priv->map, RTL930X_STORM_LB_CTRL, &lb_ctrl);
		rate = DIV_ROUND_UP_ULL(cfg->rate, 2000);
		burst = clamp_t(u64, cfg->burst, 3 * FIELD_GET(RTL930X_STORM_LB_CTRL_TOKEN, lb_ctrl),
				U16_MAX);
	}
	rate = clamp_t(u64, rate, 1, RTL930X_STORM_PORT_CTRL_RATE);

	/* spanning tree, LACP, LLDP, 802.1X and the like are never held back by a storm */
	regmap_set_bits(priv->map, RTL930X_STORM_CTRL,
			RTL930X_STORM_CTRL_ADMIT_RTKPKT | RTL930X_STORM_CTRL_ADMIT_BPDU |
			RTL930X_STORM_CTRL_ADMIT_RMA);

	regmap_update_bits(priv->map, RTL930X_STORM_PORT_MODE, BIT(port),
			   cfg->pps ? 0 : BIT(port));

	ctrl = FIELD_PREP(RTL930X_STORM_PORT_CTRL_RATE, rate) | RTL930X_STORM_PORT_CTRL_EN;
	if (type != RTLDSA_STORM_BC && !cfg->unknown_only)
		ctrl |= RTL930X_STORM_PORT_CTRL_ALL;

	regmap_write(priv->map, addr + 4, FIELD_PREP(RTL930X_STORM_PORT_BURST, burst));

	/* a flag left from an earlier meter is not this one's */
	otto_tc_930x_port_storm_exceeded(priv, port, type);

	return regmap_write(priv->map, addr, ctrl);
}

int otto_tc_931x_port_rate_police_add(struct dsa_switch *ds, int port,
				      const struct flow_action_entry *act,
				      bool ingress)
{
	struct otto_dsa_priv *priv = ds->priv;
	u32 burst;
	u64 rate;
	u32 addr;
	int err;

	/* rate has unit 16000 bit */
	rate = div_u64(act->police.rate_bytes_ps, 2000);
	rate = min_t(u64, rate, RTL93XX_BANDWIDTH_CTRL_RATE_MAX);
	rate |= RTL93XX_BANDWIDTH_CTRL_ENABLE;

	burst = min_t(u32, act->police.burst, RTL931X_BANDWIDTH_CTRL_MAX_BURST);

	if (ingress)
		addr = RTL931X_BANDWIDTH_CTRL_INGRESS(port);
	else
		addr = RTL931X_BANDWIDTH_CTRL_EGRESS(port);

	err = regmap_write(priv->map, addr + 4, burst);
	if (err)
		return err;

	return regmap_write(priv->map, addr, rate);
}

int otto_tc_931x_port_rate_police_del(struct dsa_switch *ds, int port,
				      struct flow_cls_offload *cls,
				      bool ingress)
{
	struct otto_dsa_priv *priv = ds->priv;
	u32 addr;

	if (ingress)
		addr = RTL931X_BANDWIDTH_CTRL_INGRESS(port);
	else
		addr = RTL931X_BANDWIDTH_CTRL_EGRESS(port);

	return regmap_write_bits(priv->map, addr, RTL93XX_BANDWIDTH_CTRL_ENABLE, 0);
}

static void otto_tc_tbf_apply(struct otto_dsa_priv *priv, int port, int queue, bool allowed)
{
	struct rtldsa_port *pp = &priv->ports[port];
	struct rtldsa_tbf *tbf = queue < 0 ? &pp->tbf : &pp->queue_tbf[queue];
	bool offload = allowed && tbf->handle && tbf->rate_bytes_ps && !tbf->child;

	if (offload)
		offload = !priv->r->egress_shaper_set(priv, port, queue, tbf->rate_bytes_ps,
						      tbf->burst);
	if (!offload && tbf->offloaded)
		priv->r->egress_shaper_set(priv, port, queue, 0, 0);

	tbf->offloaded = offload;
}

int otto_tc_cls_flower_add(struct dsa_switch *ds, int port,
			   struct flow_cls_offload *cls, bool ingress)
{
	struct otto_dsa_priv *priv = ds->priv;
	struct rtldsa_port *p = &priv->ports[port];
	const struct flow_action_entry *act;
	bool unknown_only;
	int ret, storm;

	/* a single rate/bandwidth limiter action on all frames is handled as port policing */
	act = otto_tc_rate_policy_extract(cls);

	/* on all broadcast, multicast or unicast frames it is storm control */
	if (act && ingress) {
		storm = otto_tc_storm_match(cls, &unknown_only);
		if (storm >= 0)
			return otto_tc_storm_add(priv, port, cls, act, storm, unknown_only);
	}

	/* everything else is offloaded to the PIE engine */
	if (!otto_tc_port_rate_police_validate(act) || !otto_tc_flower_matches_all(cls))
		return otto_tc_pie_cls_flower_add(priv, port, cls, ingress);

	if (!priv->r->port_rate_police_add)
		return -EOPNOTSUPP;

	mutex_lock(&priv->reg_mutex);

	/* only allow one offloaded police for ingress/egress */
	if (ingress && p->rate_police_ingress) {
		ret = -EOPNOTSUPP;
		goto unlock;
	}

	if (!ingress && (p->rate_police_egress || p->tbf.handle)) {
		ret = -EOPNOTSUPP;
		goto unlock;
	}

	ret = priv->r->port_rate_police_add(ds, port, act, ingress);
	if (ret < 0)
		goto unlock;

	if (ingress)
		p->rate_police_ingress = cls->cookie;
	else
		p->rate_police_egress = cls->cookie;

unlock:
	mutex_unlock(&priv->reg_mutex);

	return ret;
}

int otto_tc_cls_flower_del(struct dsa_switch *ds, int port,
			   struct flow_cls_offload *cls, bool ingress)
{
	struct otto_dsa_priv *priv = ds->priv;
	struct rtldsa_port *p = &priv->ports[port];
	int ret;

	/* PIE flower rules are ingress only. Try to remove a PIE rule first;
	 * if none exists for this cookie, fall back to port rate policing.
	 */
	if (ingress) {
		ret = otto_tc_pie_cls_flower_del(priv, cls, ingress);
		if (ret != -ENOENT)
			return ret;

		ret = otto_tc_storm_del(priv, port, cls);
		if (ret != -ENOENT)
			return ret;
	}

	if (!priv->r->port_rate_police_del)
		return -EOPNOTSUPP;

	mutex_lock(&priv->reg_mutex);

	if ((ingress ? p->rate_police_ingress : p->rate_police_egress) != cls->cookie) {
		ret = -ENOENT;
		goto unlock;
	}

	ret = priv->r->port_rate_police_del(ds, port, cls, ingress);
	if (ret < 0)
		goto unlock;

	if (ingress) {
		p->rate_police_ingress = 0;
	} else {
		p->rate_police_egress = 0;
		otto_tc_tbf_apply(priv, port, -1, true);
	}

unlock:
	mutex_unlock(&priv->reg_mutex);

	return ret;
}

int otto_tc_cls_flower_stats(struct dsa_switch *ds, int port,
			     struct flow_cls_offload *cls, bool ingress)
{
	struct otto_dsa_priv *priv = ds->priv;
	int ret;

	/* only PIE flower rules and storm meters provide per-rule statistics, and only ingress */
	if (!ingress)
		return 0;

	ret = otto_tc_pie_cls_flower_stats(priv, cls, ingress);
	if (ret == -ENOENT)
		ret = otto_tc_storm_stats(priv, port, cls);
	if (ret == -ENOENT)
		return 0;

	return ret;
}

static void otto_tc_red_stats(struct otto_dsa_priv *priv, int port, int queue,
			      struct rtldsa_red *red, struct tc_qopt_offload_stats *stats)
{
	struct net_device *user = dsa_to_port(priv->ds, port)->user;
	u64 drops = 0, bytes = red->tx_bytes, packets = red->tx_packets;
	struct rtldsa_port *pp = &priv->ports[port];
	struct rtnl_link_stats64 hw, sw;
	struct Qdisc *root;

	priv->r->red_drops_update(priv, port);
	for (int q = 0; q < MAX_PRIOS; q++)
		if (queue < 0 || q == queue)
			drops += pp->red_drops[q];

	if (queue < 0) {
		otto_stats_get64(priv->ds, port, &hw);
		dev_get_tstats64(user, &sw);
		bytes = hw.tx_bytes - sw.tx_bytes;
		packets = hw.tx_packets - sw.tx_packets;
	}

	if (stats) {
		if ((s64)(bytes - red->tx_bytes) < 0 || (s64)(packets - red->tx_packets) < 0) {
			bytes = red->tx_bytes;
			packets = red->tx_packets;
		}

		/* the kernel updates these counters under the lock of the root qdisc */
		root = rtnl_dereference(netdev_get_tx_queue(user, 0)->qdisc_sleeping);
		spin_lock_bh(qdisc_lock(root));
		stats->qstats->drops += drops - red->drops;
		stats->qstats->overlimits += drops - red->drops;
		_bstats_update(stats->bstats, bytes - red->tx_bytes, packets - red->tx_packets);
		spin_unlock_bh(qdisc_lock(root));
	}

	red->drops = drops;
	red->tx_bytes = bytes;
	red->tx_packets = packets;
}

static bool otto_tc_red_usable(const struct rtldsa_red *red)
{
	return red->handle && !red->params.is_ecn && !red->child &&
	       red->params.limit >= red->params.max;
}

static void otto_tc_red_apply(struct otto_dsa_priv *priv, int port, bool queues)
{
	const struct tc_red_qopt_offload_params *params[MAX_PRIOS] = {};
	struct rtldsa_port *pp = &priv->ports[port];
	bool root = otto_tc_red_usable(&pp->red);
	int ret;

	if (!priv->r->red_set)
		return;

	for (int queue = 0; queue < MAX_PRIOS; queue++) {
		if (root)
			params[queue] = &pp->red.params;
		else if (queues && otto_tc_red_usable(&pp->queue_red[queue]))
			params[queue] = &pp->queue_red[queue].params;
	}

	ret = priv->r->red_set(priv, port, params);

	if (root && !ret && !pp->red.offloaded)
		otto_tc_red_stats(priv, port, -1, &pp->red, NULL);
	pp->red.offloaded = root && !ret;

	for (int queue = 0; queue < MAX_PRIOS; queue++) {
		struct rtldsa_red *red = &pp->queue_red[queue];
		bool offloaded = !root && params[queue] && !ret;

		if (offloaded && !red->offloaded)
			otto_tc_red_stats(priv, port, queue, red, NULL);
		red->offloaded = offloaded;
	}

	if (priv->red_ports)
		queue_delayed_work(priv->wq, &priv->red_work, OTTO_TC_RED_POLL_INTERVAL);
}

static bool otto_tc_ets_offloaded(struct rtldsa_port *pp)
{
	if (!pp->ets_offloadable || pp->ets_children)
		return false;

	for (int queue = 0; queue < MAX_PRIOS; queue++)
		if ((pp->queue_tbf[queue].handle && !pp->queue_tbf[queue].offloaded) ||
		    (pp->queue_red[queue].handle && !pp->queue_red[queue].offloaded))
			return false;

	return true;
}

static void otto_tc_ets_apply(struct otto_dsa_priv *priv, int port)
{
	struct rtldsa_port *pp = &priv->ports[port];
	bool offload = pp->ets_offloadable && !pp->ets_children;

	for (int queue = 0; queue < MAX_PRIOS; queue++)
		otto_tc_tbf_apply(priv, port, queue, offload);
	otto_tc_red_apply(priv, port, offload);

	offload = otto_tc_ets_offloaded(pp);
	if (!offload)
		otto_tc_red_apply(priv, port, false);

	for (int queue = 0; queue < MAX_PRIOS; queue++) {
		if (!offload)
			otto_tc_tbf_apply(priv, port, queue, false);
		else if (pp->ets_weights[queue])
			priv->r->queue_sched_set(priv, port, queue, pp->ets_weights[queue], false);
		else
			priv->r->queue_sched_set(priv, port, queue, 1, true);

		if (offload && (priv->red_ports & BIT_ULL(port)) && !pp->red.offloaded &&
		    !pp->queue_red[queue].offloaded)
			dev_warn_once(priv->dev,
				      "port %d: queues without RED may drop bursts earlier\n",
				      port);
	}

	if (!offload)
		otto_qos_queue_sched_reset(priv, port);
}

/* the qdiscs on the bands of another ETS cannot be matched to a queue */
static void otto_tc_ets_clear_bands(struct rtldsa_port *pp)
{
	pp->ets_children = 0;
	for (int queue = 0; queue < MAX_PRIOS; queue++) {
		pp->queue_tbf[queue].handle = 0;
		pp->queue_red[queue].handle = 0;
		pp->queue_red_prev[queue].handle = 0;
	}
}

static void otto_tc_ets_save(struct rtldsa_port *pp)
{
	struct rtldsa_ets *prev = &pp->ets_prev;

	prev->handle = pp->ets_handle;
	prev->children = pp->ets_children;
	prev->offloadable = pp->ets_offloadable;
	memcpy(prev->weights, pp->ets_weights, sizeof(prev->weights));
	memcpy(prev->queue_tbf, pp->queue_tbf, sizeof(prev->queue_tbf));
	memcpy(prev->queue_red, pp->queue_red, sizeof(prev->queue_red));
}

static void otto_tc_ets_restore(struct rtldsa_port *pp)
{
	struct rtldsa_ets *prev = &pp->ets_prev;

	pp->ets_handle = prev->handle;
	pp->ets_children = prev->children;
	pp->ets_offloadable = prev->offloadable;
	memcpy(pp->ets_weights, prev->weights, sizeof(pp->ets_weights));
	memcpy(pp->queue_tbf, prev->queue_tbf, sizeof(pp->queue_tbf));
	memcpy(pp->queue_red, prev->queue_red, sizeof(pp->queue_red));
	prev->handle = 0;
}

/* Band 0 is the band ETS serves first and queue 7 the queue the hardware serves first.
 * The hardware maps priority n to queue n for the whole switch, so only the priomap
 * that says the same can be offloaded.
 */
static int otto_tc_setup_qdisc_ets(struct otto_dsa_priv *priv, int port,
				   struct tc_ets_qopt_offload *qopt)
{
	struct tc_ets_qopt_offload_replace_params *p = &qopt->replace_params;
	struct rtldsa_port *pp = &priv->ports[port];
	unsigned int band;
	u32 child;

	if (!priv->r->queue_sched_set || qopt->parent != TC_H_ROOT)
		return -EOPNOTSUPP;

	switch (qopt->command) {
	case TC_ETS_REPLACE:
		if (pp->ets_handle != qopt->handle) {
			otto_tc_ets_save(pp);
			otto_tc_ets_clear_bands(pp);
		}
		pp->ets_children &= GENMASK(p->bands - 1, 0);
		pp->ets_handle = qopt->handle;
		pp->ets_offloadable = p->bands == MAX_PRIOS;
		for (int band = 0; pp->ets_offloadable && band < MAX_PRIOS; band++) {
			int queue = MAX_PRIOS - 1 - band;

			pp->ets_offloadable = p->priomap[queue] == band &&
					      (!p->quanta[band] || p->weights[band]);
			pp->ets_weights[queue] = p->quanta[band] ? p->weights[band] : 0;
		}
		break;
	case TC_ETS_DESTROY:
		if (pp->ets_prev.handle == qopt->handle) {
			pp->ets_prev.handle = 0;
			return 0;
		}
		if (pp->ets_handle != qopt->handle)
			return 0;
		if (pp->ets_prev.handle) {
			otto_tc_ets_restore(pp);
			break;
		}
		pp->ets_handle = 0;
		pp->ets_offloadable = false;
		otto_tc_ets_clear_bands(pp);
		break;
	case TC_ETS_STATS:
		if (pp->ets_handle != qopt->handle)
			return -EOPNOTSUPP;
		return otto_tc_ets_offloaded(pp) ? 0 : -EOPNOTSUPP;
	case TC_ETS_GRAFT:
		if (pp->ets_handle != qopt->handle)
			return -EOPNOTSUPP;
		/* the kernel keeps a refused child, so the qdisc stays out of the hardware
		 * while any band has one, other than a TBF or RED on the queue of the band
		 */
		band = qopt->graft_params.band;
		child = qopt->graft_params.child_handle;
		if (child && (band >= MAX_PRIOS ||
			      (child != pp->queue_tbf[MAX_PRIOS - 1 - band].handle &&
			       child != pp->queue_red[MAX_PRIOS - 1 - band].handle)))
			pp->ets_children |= BIT(band);
		else
			pp->ets_children &= ~BIT(band);
		break;
	default:
		return -EOPNOTSUPP;
	}

	scoped_guard(mutex, &priv->reg_mutex)
		otto_tc_ets_apply(priv, port);

	return (otto_tc_ets_offloaded(pp) || qopt->command == TC_ETS_DESTROY) ? 0 : -EOPNOTSUPP;
}

static int otto_tc_setup_qdisc_red(struct otto_dsa_priv *priv, int port,
				   struct tc_red_qopt_offload *qopt)
{
	unsigned int band = TC_H_MIN(qopt->parent);
	struct rtldsa_port *pp = &priv->ports[port];
	struct rtldsa_red *red, *prev;
	int queue = -1;

	if (!priv->r->red_set)
		return -EOPNOTSUPP;

	if (qopt->parent == TC_H_ROOT) {
		red = &pp->red;
		prev = &pp->red_prev;
	} else if (pp->ets_handle && TC_H_MAJ(qopt->parent) == pp->ets_handle &&
		   band && band <= MAX_PRIOS) {
		queue = MAX_PRIOS - band;
		red = &pp->queue_red[queue];
		prev = &pp->queue_red_prev[queue];
	} else {
		return -EOPNOTSUPP;
	}

	switch (qopt->command) {
	case TC_RED_REPLACE:
		if (red->handle != qopt->handle) {
			*prev = *red;
			red->offloaded = false;
		}
		if (red->handle != qopt->handle || qopt->set.limit)
			red->child = false;
		red->handle = qopt->handle;
		red->params = qopt->set;
		break;
	case TC_RED_DESTROY:
		if (prev->handle == qopt->handle) {
			prev->handle = 0;
			return 0;
		}
		if (red->handle != qopt->handle)
			return 0;
		*red = *prev;
		prev->handle = 0;
		break;
	case TC_RED_STATS:
		scoped_guard(mutex, &priv->reg_mutex) {
			if (red->handle != qopt->handle || !red->offloaded)
				return -EOPNOTSUPP;
			otto_tc_red_stats(priv, port, queue, red, &qopt->stats);
		}
		return 0;
	case TC_RED_XSTATS:
		if (red->handle != qopt->handle || !(priv->red_ports & BIT_ULL(port)))
			return -EOPNOTSUPP;
		return red->offloaded ? 0 : -EOPNOTSUPP;
	case TC_RED_GRAFT:
		if (red->handle != qopt->handle)
			return -EOPNOTSUPP;
		/* a refused or deleted child stays in the kernel, deleted as the noop qdisc */
		red->child = true;
		break;
	default:
		return -EOPNOTSUPP;
	}

	scoped_guard(mutex, &priv->reg_mutex) {
		if (queue < 0 && !pp->ets_handle)
			otto_tc_red_apply(priv, port, false);
		else
			otto_tc_ets_apply(priv, port);
	}

	return (red->offloaded || qopt->command == TC_RED_DESTROY) ? 0 : -EOPNOTSUPP;
}

static int otto_tc_setup_qdisc_tbf(struct otto_dsa_priv *priv, int port,
				   struct tc_tbf_qopt_offload *qopt)
{
	const struct psched_ratecfg *rate = &qopt->replace_params.rate;
	unsigned int band = TC_H_MIN(qopt->parent);
	struct rtldsa_port *pp = &priv->ports[port];
	struct rtldsa_tbf *tbf;
	int queue = -1;

	if (!priv->r->egress_shaper_set)
		return -EOPNOTSUPP;

	if (qopt->parent == TC_H_ROOT) {
		tbf = &pp->tbf;
	} else if (pp->ets_handle && TC_H_MAJ(qopt->parent) == pp->ets_handle &&
		   band && band <= MAX_PRIOS) {
		queue = MAX_PRIOS - band;
		tbf = &pp->queue_tbf[queue];
	} else {
		return -EOPNOTSUPP;
	}

	switch (qopt->command) {
	case TC_TBF_REPLACE:
		if (tbf->handle != qopt->handle)
			tbf->child = false;
		tbf->handle = qopt->handle;
		/* the limiters know no overhead, minimum size or ATM cells, so a TBF that
		 * uses them gets no rate and stays in software
		 */
		if (rate->overhead || rate->mpu || rate->linklayer == TC_LINKLAYER_ATM)
			tbf->rate_bytes_ps = 0;
		else
			tbf->rate_bytes_ps = rate->rate_bytes_ps;
		tbf->burst = qopt->replace_params.max_size;
		break;
	case TC_TBF_DESTROY:
		if (tbf->handle != qopt->handle)
			return 0;
		tbf->handle = 0;
		break;
	case TC_TBF_STATS:
		return tbf->handle == qopt->handle && tbf->offloaded ? 0 : -EOPNOTSUPP;
	case TC_TBF_GRAFT:
		if (tbf->handle != qopt->handle)
			return -EOPNOTSUPP;
		/* a refused or deleted child stays in the kernel, deleted as the noop qdisc */
		tbf->child = true;
		break;
	default:
		return -EOPNOTSUPP;
	}

	scoped_guard(mutex, &priv->reg_mutex) {
		/* the egress police uses the shaper of the port */
		if (queue < 0)
			otto_tc_tbf_apply(priv, port, queue, !pp->rate_police_egress);
		else
			otto_tc_ets_apply(priv, port);
	}

	return (tbf->offloaded || qopt->command == TC_TBF_DESTROY) ? 0 : -EOPNOTSUPP;
}

int otto_tc_port_setup_tc(struct dsa_switch *ds, int port, enum tc_setup_type type,
			  void *type_data)
{
	struct otto_dsa_priv *priv = ds->priv;

	switch (type) {
	case TC_SETUP_QDISC_RED:
		return otto_tc_setup_qdisc_red(priv, port, type_data);
	case TC_SETUP_QDISC_TBF:
		return otto_tc_setup_qdisc_tbf(priv, port, type_data);
	case TC_SETUP_QDISC_ETS:
		return otto_tc_setup_qdisc_ets(priv, port, type_data);
	default:
		return -EOPNOTSUPP;
	}
}
