/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_SOC_REALTEK_OTTO_ETH_H
#define _LINUX_SOC_REALTEK_OTTO_ETH_H

#include <linux/netdevice.h>

/*
 * Receive hook of the Otto ethernet driver (rtl838x_eth).
 *
 * The switch driver installs it on its conduit to learn the CPU tag reason of
 * every frame the switch hands to the CPU (it reports them as devlink traps),
 * and owns the mapping of reasons to CPU queues while it is installed: the
 * ethernet driver then leaves that mapping alone when it (re)opens. The hook
 * runs in NAPI context, once per received frame, before the frame enters the
 * stack.
 */
typedef void (*otto_eth_rx_hook_t)(void *ctx, struct sk_buff *skb, int port, int reason);

/*
 * Install (hook != NULL) or remove (hook == NULL) the receive hook of @dev.
 * Removing it waits until no receive path still runs the old hook.
 * Returns -ENODEV if @dev is not an Otto ethernet device and -EBUSY if a
 * different hook is installed.
 */
int otto_eth_set_rx_hook(struct net_device *dev, otto_eth_rx_hook_t hook, void *ctx);

/* Number of CPU receive queues the ethernet driver serves on @dev, 0 if not an Otto device. */
int otto_eth_rx_queues(struct net_device *dev);

#endif /* _LINUX_SOC_REALTEK_OTTO_ETH_H */
