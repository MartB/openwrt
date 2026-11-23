#
# Front-panel LED mode for the Zyxel XMG1915 switches.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=xmg1915-leds
PKG_VERSION:=1
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0-or-later
PKG_MAINTAINER:=Martin <martin@familie-boeh.de>

include $(INCLUDE_DIR)/package.mk

define Package/xmg1915-leds
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Front-panel LED mode for Zyxel XMG1915 switches
  PKGARCH:=all
endef

define Package/xmg1915-leds/description
 led-mode turns the front-panel port LEDs off and back to link speed, as the
 stock firmware's LED-mode button does, and restores the chosen mode at boot.
 On the PoE models (with xmg1915-poe-leds) it also has the PoE class display,
 and the LED-mode button cycles through the modes.

 Requires the rtl930x software-LED driver and port LEDs in the device tree.
endef

define Package/xmg1915-leds/conffiles
/etc/config/led-mode
/etc/rc.button/BTN_1
endef

# nothing to build; the payload is shell
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/xmg1915-leds/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/usr/sbin/led-mode $(1)/usr/sbin/led-mode
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/led-mode $(1)/etc/init.d/led-mode
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/led-mode $(1)/etc/config/led-mode
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/90-led-mode $(1)/etc/uci-defaults/90-led-mode
	$(INSTALL_DIR) $(1)/etc/rc.button
	$(INSTALL_BIN) ./files/etc/rc.button/BTN_1 $(1)/etc/rc.button/BTN_1
endef

$(eval $(call BuildPackage,xmg1915-leds))
