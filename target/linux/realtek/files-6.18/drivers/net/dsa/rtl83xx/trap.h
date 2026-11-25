/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _OTTO_TRAP_H
#define _OTTO_TRAP_H

#include <net/devlink.h>

struct dsa_switch;
struct otto_dsa_priv;

int otto_trap_setup(struct otto_dsa_priv *priv);
void otto_trap_teardown(struct otto_dsa_priv *priv);

int otto_trap_init(struct dsa_switch *ds, const struct devlink_trap *trap, void *trap_ctx);
void otto_trap_fini(struct dsa_switch *ds, const struct devlink_trap *trap, void *trap_ctx);
int otto_trap_action_set(struct dsa_switch *ds, const struct devlink_trap *trap,
			 enum devlink_trap_action action, struct netlink_ext_ack *extack);
int otto_trap_group_init(struct dsa_switch *ds, const struct devlink_trap_group *group);
int otto_trap_group_set(struct dsa_switch *ds, const struct devlink_trap_group *group,
			const struct devlink_trap_policer *policer,
			struct netlink_ext_ack *extack);
int otto_trap_policer_init(struct dsa_switch *ds, const struct devlink_trap_policer *policer);
void otto_trap_policer_fini(struct dsa_switch *ds, const struct devlink_trap_policer *policer);
int otto_trap_policer_set(struct dsa_switch *ds, const struct devlink_trap_policer *policer,
			  u64 rate, u64 burst, struct netlink_ext_ack *extack);
int otto_trap_policer_counter_get(struct dsa_switch *ds,
				  const struct devlink_trap_policer *policer, u64 *p_drops);

#endif /* _OTTO_TRAP_H */
