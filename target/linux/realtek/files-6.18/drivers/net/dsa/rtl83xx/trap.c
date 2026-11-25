// SPDX-License-Identifier: GPL-2.0-only
/*
 * Control plane policing for RTL930x through devlink packet traps.
 *
 * Every frame the switch hands to the CPU carries a reason in its CPU tag and
 * enters one of 32 CPU queues. Which queue is set per kind of frame by 5-bit
 * fields in QM_RSN2CPUQID_CTRL_0..8 and QM_FLAG2CPUQID_CTRL_0..1, and every
 * CPU queue has a token bucket of its own (EGBW_CPU_Q_MAX_LB_CTRL) that counts
 * packets and tail drops in hardware. A full queue does not hold up the
 * others.
 *
 * That maps onto devlink as follows:
 * - a trap is a kind of frame: the queue fields that steer it and the CPU tag
 *   reasons it arrives with (for the per-trap statistics);
 * - trap policer n is the token bucket of CPU queue n (n = 1..7);
 * - binding a trap group to policer n points the fields of the group's traps
 *   at queue n. A group without a policer, and every kind of frame no trap
 *   covers, goes to queue 0, which is not policed.
 *
 * The ethernet driver serves one receive ring per CPU queue and calls
 * otto_trap_rx() for every frame, which counts it against its trap.
 */

#include <linux/bitfield.h>
#include <linux/hrtimer.h>
#include <linux/regmap.h>
#include <linux/soc/realtek/otto_eth.h>
#include <linux/spinlock.h>
#include <net/devlink.h>
#include <net/dsa.h>

#include "otto_dsa.h"
#include "trap.h"

#define RTL930X_QM_RSN2CPUQID_CTRL(n)		(0xa344 + (n) * 4)	/* n = 0..8 */
#define RTL930X_QM_FLAG2CPUQID_CTRL(n)		(0xa368 + (n) * 4)	/* n = 0..1 */
#define RTL930X_QM_CPUQID_REGS			11
#define RTL930X_QM_CPUQID_FIELD			GENMASK(4, 0)

/* Token bucket of CPU queue q: word 0 enable and rate, word 1 burst */
#define RTL930X_EGBW_CPU_Q_MAX_LB_CTRL(q)	(0x7cb8 + (q) * 8)
#define RTL930X_EGBW_CPU_Q_MAX_LB_BURST(q)	(0x7cbc + (q) * 8)
#define RTL930X_EGBW_CPU_Q_EN			BIT(20)
#define RTL930X_EGBW_CPU_Q_RATE			GENMASK(19, 0)
#define RTL930X_EGBW_CPU_Q_BURST		GENMASK(15, 0)
#define RTL930X_EGBW_CPU_Q_BURST_DEFAULT	0x8000

/*
 * Frames CPU queue q dropped (STAT_PORT_E_DROP_CNTR2, port 28). The counter
 * is 16 bits wide, free running and wraps; a flood can wrap it many times a
 * second, so it is polled often enough to stay below one wrap per poll:
 * 65535 drops per 5 ms is 13M frames/s, against about 3M frames/s measured
 * from a loop of two 2.5G ports flooding the CPU.
 */
#define RTL930X_STAT_CPU_Q_DROP_CNTR(q)		(0xbd64 + (q) * 4)
#define RTL930X_STAT_CPU_Q_DROP			GENMASK(15, 0)
#define OTTO_TRAP_DROP_POLL_NS			(5 * NSEC_PER_MSEC)

#define OTTO_TRAP_CPU_QUEUES			8	/* queue 0 + one per policer */
#define OTTO_TRAP_POLICERS			(OTTO_TRAP_CPU_QUEUES - 1)
#define OTTO_TRAP_REASONS			64	/* 6-bit CPU tag reason */

enum {
	OTTO_TRAP_POLICER_L2_CONTROL = 1,
	OTTO_TRAP_POLICER_MC_SNOOPING,
	OTTO_TRAP_POLICER_LOCAL_DELIVERY,
	OTTO_TRAP_POLICER_L3_EXCEPTIONS,
	OTTO_TRAP_POLICER_FLOOD,
	OTTO_TRAP_POLICER_SPARE1,
	OTTO_TRAP_POLICER_SPARE2,
};

enum {
	OTTO_TRAP_GROUP_L2_FLOOD = DEVLINK_TRAP_GROUP_GENERIC_ID_MAX + 1,
};

enum {
	OTTO_TRAP_ID_IGMP_MLD = DEVLINK_TRAP_GENERIC_ID_MAX + 1,
	OTTO_TRAP_ID_L3_EXCEPTION,
	OTTO_TRAP_ID_FLOOD_TO_CPU,
};

struct otto_trap_field {
	u8 reg;		/* QM_RSN2CPUQID_CTRL_<reg>, 9 and 10 are QM_FLAG2CPUQID_CTRL_0/1 */
	u8 shift;
};

struct otto_trap_info {
	u16 id;				/* devlink trap id */
	const struct otto_trap_field *fields;
	u8 n_fields;
	const u8 *reasons;
	u8 n_reasons;
};

struct otto_trap_ctrl {
	struct otto_dsa_priv *priv;
	struct net_device *conduit;
	void *reason_ctx[OTTO_TRAP_REASONS];
	struct devlink_port *dl_port[57];
	bool registered;

	/* policer drop counters: 64-bit sums of the 16-bit hardware counters */
	struct hrtimer drop_timer;
	spinlock_t drop_lock;		/* drop_last, drops */
	u16 drop_last[OTTO_TRAP_CPU_QUEUES];
	u64 drops[OTTO_TRAP_CPU_QUEUES];
};

#define FIELD_AT(_reg, _shift)	{ .reg = (_reg), .shift = (_shift) }

static const struct otto_trap_field stp_fields[] = { FIELD_AT(2, 15) };		/* RMA_BPDU */
static const struct otto_trap_field lacp_fields[] = { FIELD_AT(2, 10) };	/* RMA_LACP */
static const struct otto_trap_field lldp_fields[] = { FIELD_AT(2, 5) };		/* RMA_LLDP */
static const struct otto_trap_field eapol_fields[] = { FIELD_AT(2, 0) };	/* RMA_EAPOL */
static const struct otto_trap_field igmp_mld_fields[] = { FIELD_AT(6, 0) };	/* IGMP_MLD */
static const struct otto_trap_field local_route_fields[] = {
	FIELD_AT(5, 25),	/* L3_UC_HOST_ROUTE: addresses of the switch itself */
	FIELD_AT(3, 20),	/* ROUTER_MAC_IF */
};
static const struct otto_trap_field l3_exception_fields[] = {
	FIELD_AT(0, 10),	/* L3_IPUC_RPF */
	FIELD_AT(3, 15),	/* L3_IPUC_NON_IP_PKT */
	FIELD_AT(3, 10),	/* IP4_IP6_HDR_ERR */
	FIELD_AT(3, 5),		/* ROUTING_IP_CHK */
	FIELD_AT(3, 0),		/* L3_ROUTING_DIP_DMAC_MISMATCH */
	FIELD_AT(4, 25),	/* IP6_UC_MC_HOP_BY_HOP */
	FIELD_AT(4, 20),	/* IP6_UC_MC_ROUTING_HDR */
	FIELD_AT(4, 15),	/* IP4_IP_OPT */
	FIELD_AT(4, 10),	/* IP4_IP6_MC_ROUTING_LU_MISS */
	FIELD_AT(4, 5),		/* L3_IPUC_NULL_ROUTE */
	FIELD_AT(4, 0),		/* L3_IPUC_PBR_NULL_ROUTE */
	FIELD_AT(5, 20),	/* L3_UC_NET_ROUTE */
	FIELD_AT(5, 15),	/* L3_MC_BRIDGE_ENTRY */
	FIELD_AT(5, 10),	/* L3_MC_ROUTE_ENTRY */
	FIELD_AT(5, 5),		/* L3_IPMC_RPF */
	FIELD_AT(5, 0),		/* ROUTING_EXCPT_NH_AGE_OUT_ACT */
	FIELD_AT(6, 25),	/* IP4_IP6_ICMP_REDRT */
	FIELD_AT(6, 20),	/* IPUC_MTU */
	FIELD_AT(6, 15),	/* IPMC_MTU */
	FIELD_AT(6, 10),	/* IPUC_TTL */
	FIELD_AT(6, 5),		/* IPMC_TTL */
};
static const struct otto_trap_field flood_fields[] = { FIELD_AT(8, 0) };	/* NORMAL_FWD */

/* CPU tag reasons (Realtek SDK nic_rtl9300.c reasonTbl) */
static const u8 stp_reasons[] = { 24 };
static const u8 lacp_reasons[] = { 25 };
static const u8 lldp_reasons[] = { 26 };
static const u8 eapol_reasons[] = { 27 };
static const u8 igmp_mld_reasons[] = { 55 };
static const u8 local_route_reasons[] = { 31, 42 };
static const u8 l3_exception_reasons[] = {
	13, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 43, 44, 45, 46, 48, 51, 52, 53, 54,
};
static const u8 flood_reasons[] = { 63 };

#define TRAP_INFO(_id, _name)						\
	{								\
		.id = (_id),						\
		.fields = _name##_fields,				\
		.n_fields = ARRAY_SIZE(_name##_fields),			\
		.reasons = _name##_reasons,				\
		.n_reasons = ARRAY_SIZE(_name##_reasons),		\
	}

static const struct otto_trap_info otto_trap_infos[] = {
	TRAP_INFO(DEVLINK_TRAP_GENERIC_ID_STP, stp),
	TRAP_INFO(DEVLINK_TRAP_GENERIC_ID_LACP, lacp),
	TRAP_INFO(DEVLINK_TRAP_GENERIC_ID_LLDP, lldp),
	TRAP_INFO(DEVLINK_TRAP_GENERIC_ID_EAPOL, eapol),
	TRAP_INFO(OTTO_TRAP_ID_IGMP_MLD, igmp_mld),
	TRAP_INFO(DEVLINK_TRAP_GENERIC_ID_LOCAL_ROUTE, local_route),
	TRAP_INFO(OTTO_TRAP_ID_L3_EXCEPTION, l3_exception),
	TRAP_INFO(OTTO_TRAP_ID_FLOOD_TO_CPU, flood),
};

#define OTTO_TRAP_CONTROL(_id, _group)					\
	DEVLINK_TRAP_GENERIC(CONTROL, TRAP, _id,			\
			     DEVLINK_TRAP_GROUP_GENERIC_ID_##_group,	\
			     DEVLINK_TRAP_METADATA_TYPE_F_IN_PORT)

static const struct devlink_trap otto_traps[] = {
	OTTO_TRAP_CONTROL(STP, STP),
	OTTO_TRAP_CONTROL(LACP, LACP),
	OTTO_TRAP_CONTROL(LLDP, LLDP),
	OTTO_TRAP_CONTROL(EAPOL, EAPOL),
	DEVLINK_TRAP_DRIVER(CONTROL, TRAP, OTTO_TRAP_ID_IGMP_MLD, "igmp_mld",
			    DEVLINK_TRAP_GROUP_GENERIC_ID_MC_SNOOPING,
			    DEVLINK_TRAP_METADATA_TYPE_F_IN_PORT),
	OTTO_TRAP_CONTROL(LOCAL_ROUTE, LOCAL_DELIVERY),
	DEVLINK_TRAP_DRIVER(EXCEPTION, TRAP, OTTO_TRAP_ID_L3_EXCEPTION, "l3_exception",
			    DEVLINK_TRAP_GROUP_GENERIC_ID_L3_EXCEPTIONS,
			    DEVLINK_TRAP_METADATA_TYPE_F_IN_PORT),
	DEVLINK_TRAP_DRIVER(CONTROL, TRAP, OTTO_TRAP_ID_FLOOD_TO_CPU, "flood_to_cpu",
			    OTTO_TRAP_GROUP_L2_FLOOD,
			    DEVLINK_TRAP_METADATA_TYPE_F_IN_PORT),
};

static const struct devlink_trap_group otto_trap_groups[] = {
	DEVLINK_TRAP_GROUP_GENERIC(STP, OTTO_TRAP_POLICER_L2_CONTROL),
	DEVLINK_TRAP_GROUP_GENERIC(LACP, OTTO_TRAP_POLICER_L2_CONTROL),
	DEVLINK_TRAP_GROUP_GENERIC(LLDP, OTTO_TRAP_POLICER_L2_CONTROL),
	DEVLINK_TRAP_GROUP_GENERIC(EAPOL, OTTO_TRAP_POLICER_L2_CONTROL),
	DEVLINK_TRAP_GROUP_GENERIC(MC_SNOOPING, OTTO_TRAP_POLICER_MC_SNOOPING),
	DEVLINK_TRAP_GROUP_GENERIC(LOCAL_DELIVERY, OTTO_TRAP_POLICER_LOCAL_DELIVERY),
	DEVLINK_TRAP_GROUP_GENERIC(L3_EXCEPTIONS, OTTO_TRAP_POLICER_L3_EXCEPTIONS),
	{
		.name = "l2_flood",
		.id = OTTO_TRAP_GROUP_L2_FLOOD,
		.generic = false,
		.init_policer_id = OTTO_TRAP_POLICER_FLOOD,
	},
};

/* The token bucket rate and burst fields bound what a policer accepts */
#define OTTO_TRAP_POLICER(_id, _rate, _burst)				\
	DEVLINK_TRAP_POLICER(_id, _rate, _burst, RTL930X_EGBW_CPU_Q_RATE, 1,	\
			     RTL930X_EGBW_CPU_Q_BURST, 1)

/*
 * Defaults in packets per second and packets. Measured on an XMG1915 the CPU
 * takes about 10k frames/s before one VPE is busy with nothing but softirq,
 * and a flood capped at 2000/s costs it about 20%. Every policed queue sits
 * well below that, so a storm on one of them leaves room for the rest.
 */
static const struct devlink_trap_policer otto_trap_policers[] = {
	OTTO_TRAP_POLICER(OTTO_TRAP_POLICER_L2_CONTROL, 512, 128),
	OTTO_TRAP_POLICER(OTTO_TRAP_POLICER_MC_SNOOPING, 1024, 256),
	OTTO_TRAP_POLICER(OTTO_TRAP_POLICER_LOCAL_DELIVERY, 4000, 512),
	OTTO_TRAP_POLICER(OTTO_TRAP_POLICER_L3_EXCEPTIONS, 1000, 256),
	OTTO_TRAP_POLICER(OTTO_TRAP_POLICER_FLOOD, 2000, 512),
	OTTO_TRAP_POLICER(OTTO_TRAP_POLICER_SPARE1, 1000, 256),
	OTTO_TRAP_POLICER(OTTO_TRAP_POLICER_SPARE2, 1000, 256),
};

static_assert(ARRAY_SIZE(otto_trap_policers) == OTTO_TRAP_POLICERS);
static_assert(ARRAY_SIZE(otto_traps) == ARRAY_SIZE(otto_trap_infos));

static u32 otto_trap_field_reg(const struct otto_trap_field *f)
{
	return f->reg < 9 ? RTL930X_QM_RSN2CPUQID_CTRL(f->reg) :
			    RTL930X_QM_FLAG2CPUQID_CTRL(f->reg - 9);
}

static const struct otto_trap_info *otto_trap_info_find(u16 id)
{
	for (int i = 0; i < ARRAY_SIZE(otto_trap_infos); i++)
		if (otto_trap_infos[i].id == id)
			return &otto_trap_infos[i];

	return NULL;
}

static void otto_trap_steer(struct otto_dsa_priv *priv, const struct otto_trap_info *info,
			    unsigned int queue)
{
	for (int i = 0; i < info->n_fields; i++) {
		const struct otto_trap_field *f = &info->fields[i];

		regmap_update_bits(priv->map, otto_trap_field_reg(f),
				   RTL930X_QM_CPUQID_FIELD << f->shift, queue << f->shift);
	}
}

/* Point every trap of @group at the queue of @policer_id (0: unpoliced queue 0) */
static void otto_trap_group_steer(struct otto_dsa_priv *priv, u16 group_id, u32 policer_id)
{
	for (int i = 0; i < ARRAY_SIZE(otto_traps); i++) {
		if (otto_traps[i].init_group_id != group_id)
			continue;

		otto_trap_steer(priv, &otto_trap_infos[i], policer_id);
	}
}

static void otto_trap_bucket_set(struct otto_dsa_priv *priv, unsigned int queue,
				 u32 rate, u32 burst, bool enable)
{
	regmap_write(priv->map, RTL930X_EGBW_CPU_Q_MAX_LB_BURST(queue),
		     FIELD_PREP(RTL930X_EGBW_CPU_Q_BURST, burst));
	regmap_write(priv->map, RTL930X_EGBW_CPU_Q_MAX_LB_CTRL(queue),
		     (enable ? RTL930X_EGBW_CPU_Q_EN : 0) |
		     FIELD_PREP(RTL930X_EGBW_CPU_Q_RATE, rate));
}

/* Fold the hardware drop counters of the policed queues into the 64-bit sums */
static void otto_trap_drops_update(struct otto_trap_ctrl *ctrl)
{
	struct regmap *map = ctrl->priv->map;
	unsigned long flags;
	u32 v;

	spin_lock_irqsave(&ctrl->drop_lock, flags);
	for (int q = 1; q < OTTO_TRAP_CPU_QUEUES; q++) {
		u16 cur;

		if (regmap_read(map, RTL930X_STAT_CPU_Q_DROP_CNTR(q), &v))
			continue;

		cur = FIELD_GET(RTL930X_STAT_CPU_Q_DROP, v);
		ctrl->drops[q] += (u16)(cur - ctrl->drop_last[q]);
		ctrl->drop_last[q] = cur;
	}
	spin_unlock_irqrestore(&ctrl->drop_lock, flags);
}

static enum hrtimer_restart otto_trap_drop_timer(struct hrtimer *timer)
{
	struct otto_trap_ctrl *ctrl = container_of(timer, struct otto_trap_ctrl, drop_timer);

	otto_trap_drops_update(ctrl);
	hrtimer_forward_now(timer, ns_to_ktime(OTTO_TRAP_DROP_POLL_NS));

	return HRTIMER_RESTART;
}

static void otto_trap_drops_start(struct otto_trap_ctrl *ctrl)
{
	u32 v;

	spin_lock_init(&ctrl->drop_lock);
	for (int q = 1; q < OTTO_TRAP_CPU_QUEUES; q++)
		if (!regmap_read(ctrl->priv->map, RTL930X_STAT_CPU_Q_DROP_CNTR(q), &v))
			ctrl->drop_last[q] = FIELD_GET(RTL930X_STAT_CPU_Q_DROP, v);

	hrtimer_setup(&ctrl->drop_timer, otto_trap_drop_timer, CLOCK_MONOTONIC,
		      HRTIMER_MODE_REL_SOFT);
	hrtimer_start(&ctrl->drop_timer, ns_to_ktime(OTTO_TRAP_DROP_POLL_NS),
		      HRTIMER_MODE_REL_SOFT);
}

int otto_trap_policer_counter_get(struct dsa_switch *ds,
				  const struct devlink_trap_policer *policer, u64 *p_drops)
{
	struct otto_dsa_priv *priv = ds->priv;
	struct otto_trap_ctrl *ctrl = priv->trap_ctrl;
	unsigned long flags;

	if (!ctrl || policer->id >= OTTO_TRAP_CPU_QUEUES)
		return -EOPNOTSUPP;

	otto_trap_drops_update(ctrl);
	spin_lock_irqsave(&ctrl->drop_lock, flags);
	*p_drops = ctrl->drops[policer->id];
	spin_unlock_irqrestore(&ctrl->drop_lock, flags);

	return 0;
}

static void otto_trap_rx(void *ctx, struct sk_buff *skb, int port, int reason)
{
	struct otto_trap_ctrl *ctrl = ctx;
	void *trap_ctx;

	if (unlikely(reason < 0 || reason >= OTTO_TRAP_REASONS))
		return;

	trap_ctx = READ_ONCE(ctrl->reason_ctx[reason]);
	if (!trap_ctx)
		return;

	devlink_trap_report(ctrl->priv->ds->devlink, skb, trap_ctx,
			    port < ARRAY_SIZE(ctrl->dl_port) ? ctrl->dl_port[port] : NULL,
			    NULL);
}

int otto_trap_init(struct dsa_switch *ds, const struct devlink_trap *trap, void *trap_ctx)
{
	struct otto_dsa_priv *priv = ds->priv;
	const struct otto_trap_info *info;

	if (!priv->trap_ctrl)
		return -EOPNOTSUPP;

	info = otto_trap_info_find(trap->id);
	if (!info)
		return -EINVAL;

	for (int i = 0; i < info->n_reasons; i++)
		WRITE_ONCE(priv->trap_ctrl->reason_ctx[info->reasons[i]], trap_ctx);

	return 0;
}

void otto_trap_fini(struct dsa_switch *ds, const struct devlink_trap *trap, void *trap_ctx)
{
	struct otto_dsa_priv *priv = ds->priv;
	const struct otto_trap_info *info;

	if (!priv->trap_ctrl)
		return;

	info = otto_trap_info_find(trap->id);
	if (!info)
		return;

	for (int i = 0; i < info->n_reasons; i++)
		WRITE_ONCE(priv->trap_ctrl->reason_ctx[info->reasons[i]], NULL);
}

int otto_trap_action_set(struct dsa_switch *ds, const struct devlink_trap *trap,
			 enum devlink_trap_action action, struct netlink_ext_ack *extack)
{
	/*
	 * The switch keeps trapping these frames: STP, LACP and IGMP snooping
	 * run on the CPU, and the CPU port is part of every flood domain.
	 * Mirroring (forward and copy) is not offered.
	 */
	if (action != DEVLINK_TRAP_ACTION_TRAP) {
		NL_SET_ERR_MSG_MOD(extack, "Only the trap action is supported");
		return -EOPNOTSUPP;
	}

	return 0;
}

int otto_trap_group_init(struct dsa_switch *ds, const struct devlink_trap_group *group)
{
	struct otto_dsa_priv *priv = ds->priv;

	if (!priv->trap_ctrl)
		return -EOPNOTSUPP;

	otto_trap_group_steer(priv, group->id, group->init_policer_id);

	return 0;
}

int otto_trap_group_set(struct dsa_switch *ds, const struct devlink_trap_group *group,
			const struct devlink_trap_policer *policer,
			struct netlink_ext_ack *extack)
{
	struct otto_dsa_priv *priv = ds->priv;

	if (!priv->trap_ctrl)
		return -EOPNOTSUPP;

	otto_trap_group_steer(priv, group->id, policer ? policer->id : 0);

	return 0;
}

int otto_trap_policer_init(struct dsa_switch *ds, const struct devlink_trap_policer *policer)
{
	struct otto_dsa_priv *priv = ds->priv;

	if (!priv->trap_ctrl)
		return -EOPNOTSUPP;

	otto_trap_bucket_set(priv, policer->id, policer->init_rate, policer->init_burst, true);

	return 0;
}

void otto_trap_policer_fini(struct dsa_switch *ds, const struct devlink_trap_policer *policer)
{
	struct otto_dsa_priv *priv = ds->priv;

	if (!priv->trap_ctrl)
		return;

	otto_trap_bucket_set(priv, policer->id, RTL930X_EGBW_CPU_Q_RATE,
			     RTL930X_EGBW_CPU_Q_BURST_DEFAULT, false);
}

int otto_trap_policer_set(struct dsa_switch *ds, const struct devlink_trap_policer *policer,
			  u64 rate, u64 burst, struct netlink_ext_ack *extack)
{
	struct otto_dsa_priv *priv = ds->priv;

	if (!priv->trap_ctrl)
		return -EOPNOTSUPP;

	/* devlink has checked rate and burst against the policer's bounds */
	otto_trap_bucket_set(priv, policer->id, rate, burst, true);

	return 0;
}

int otto_trap_setup(struct otto_dsa_priv *priv)
{
	struct dsa_switch *ds = priv->ds;
	struct otto_trap_ctrl *ctrl;
	struct net_device *conduit;
	struct dsa_port *dp;
	int err;

	if (priv->family_id != RTL9300_FAMILY_ID)
		return 0;

	dp = dsa_to_port(ds, priv->r->cpu_port);
	conduit = dp ? dp->conduit : NULL;
	if (!conduit || otto_eth_rx_queues(conduit) < OTTO_TRAP_CPU_QUEUES) {
		dev_warn(priv->dev, "conduit serves too few CPU queues, no packet traps\n");
		return 0;
	}

	ctrl = devm_kzalloc(priv->dev, sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl)
		return -ENOMEM;

	ctrl->priv = priv;
	ctrl->conduit = conduit;
	dsa_switch_for_each_user_port(dp, ds)
		if (dp->index < ARRAY_SIZE(ctrl->dl_port))
			ctrl->dl_port[dp->index] = &dp->devlink_port;

	/*
	 * The CPU queue buckets count packets with EGBW_CTRL at its reset
	 * value. Everything goes to queue 0 until a trap group claims it.
	 */
	for (int i = 0; i < RTL930X_QM_CPUQID_REGS; i++)
		regmap_write(priv->map, i < 9 ? RTL930X_QM_RSN2CPUQID_CTRL(i) :
					    RTL930X_QM_FLAG2CPUQID_CTRL(i - 9), 0);

	priv->trap_ctrl = ctrl;

	devl_lock(ds->devlink);
	err = devl_trap_policers_register(ds->devlink, otto_trap_policers,
					  ARRAY_SIZE(otto_trap_policers));
	if (err)
		goto err_unlock;

	err = devl_trap_groups_register(ds->devlink, otto_trap_groups,
					ARRAY_SIZE(otto_trap_groups));
	if (err)
		goto err_policers;

	err = devl_traps_register(ds->devlink, otto_traps, ARRAY_SIZE(otto_traps), priv);
	if (err)
		goto err_groups;
	devl_unlock(ds->devlink);

	err = otto_eth_set_rx_hook(conduit, otto_trap_rx, ctrl);
	if (err) {
		dev_warn(priv->dev, "cannot hook the conduit receive path (%d), no trap statistics\n",
			 err);
		/* policing works without it */
	}

	otto_trap_drops_start(ctrl);
	ctrl->registered = true;
	dev_info(priv->dev, "%zu packet traps in %zu groups, %d CPU queue policers\n",
		 ARRAY_SIZE(otto_traps), ARRAY_SIZE(otto_trap_groups), OTTO_TRAP_POLICERS);

	return 0;

err_groups:
	devl_trap_groups_unregister(ds->devlink, otto_trap_groups, ARRAY_SIZE(otto_trap_groups));
err_policers:
	devl_trap_policers_unregister(ds->devlink, otto_trap_policers,
				      ARRAY_SIZE(otto_trap_policers));
err_unlock:
	devl_unlock(ds->devlink);
	priv->trap_ctrl = NULL;
	dev_err(priv->dev, "packet trap registration failed: %d\n", err);

	return err;
}

void otto_trap_teardown(struct otto_dsa_priv *priv)
{
	struct otto_trap_ctrl *ctrl = priv->trap_ctrl;
	struct dsa_switch *ds = priv->ds;

	if (!ctrl || !ctrl->registered)
		return;

	otto_eth_set_rx_hook(ctrl->conduit, NULL, NULL);
	hrtimer_cancel(&ctrl->drop_timer);

	devl_lock(ds->devlink);
	devl_traps_unregister(ds->devlink, otto_traps, ARRAY_SIZE(otto_traps));
	devl_trap_groups_unregister(ds->devlink, otto_trap_groups, ARRAY_SIZE(otto_trap_groups));
	devl_trap_policers_unregister(ds->devlink, otto_trap_policers,
				      ARRAY_SIZE(otto_trap_policers));
	devl_unlock(ds->devlink);

	ctrl->registered = false;
	priv->trap_ctrl = NULL;
}
