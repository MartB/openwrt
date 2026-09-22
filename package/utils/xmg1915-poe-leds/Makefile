#
# Front-panel PoE LED support for the Zyxel XMG1915-10EP.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=xmg1915-poe-leds
PKG_VERSION:=1
PKG_RELEASE:=7

PKG_LICENSE:=GPL-2.0-or-later
PKG_MAINTAINER:=Martin <martin@familie-boeh.de>

include $(INCLUDE_DIR)/package.mk

define Package/xmg1915-poe-leds
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Front-panel PoE LED support for Zyxel XMG1915-10EP
  DEPENDS:=+ethtool-full
  PKGARCH:=all
endef

define Package/xmg1915-poe-leds/description
 Drives the front-panel PoE indicator and the LED-mode button, reproducing the
 stock firmware's behaviour on OpenWrt.

 poe-led shows the PoE budget on the system indicator: green with at least 20%
 of the budget free, amber between 5% and 20%, red below that or on a fault.

 led-mode switches the port LEDs between link speed and PoE class - yellow for
 802.3af, green for 802.3at, blue for 802.3bt - or turns the panel off.

 Requires the rtl930x software-LED driver.
endef

define Package/xmg1915-poe-leds/conffiles
/etc/config/poe-led
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

define Package/xmg1915-poe-leds/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/usr/sbin/poe-led  $(1)/usr/sbin/poe-led
	$(INSTALL_BIN) ./files/usr/sbin/led-mode $(1)/usr/sbin/led-mode
	$(INSTALL_BIN) ./files/usr/sbin/boardinfo $(1)/usr/sbin/boardinfo
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/poe-led $(1)/etc/init.d/poe-led
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/poe-led $(1)/etc/config/poe-led
	$(INSTALL_DIR) $(1)/etc/rc.button
	$(INSTALL_BIN) ./files/etc/rc.button/BTN_1 $(1)/etc/rc.button/BTN_1
endef

$(eval $(call BuildPackage,xmg1915-poe-leds))
