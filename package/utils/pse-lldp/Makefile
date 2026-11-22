include $(TOPDIR)/rules.mk

PKG_NAME:=pse-lldp
PKG_VERSION:=1
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0-or-later
PKG_MAINTAINER:=Martin <martin@familie-boeh.de>

include $(INCLUDE_DIR)/package.mk

define Package/pse-lldp
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=Answer LLDP PoE power requests
  DEPENDS:=+lldpd +ethtool-full +ucode +ucode-mod-fs +ucode-mod-uci +ucode-mod-uloop
  PKGARCH:=all
endef

define Package/pse-lldp/description
 Reads the power that powered devices request over LLDP (802.3at DLL or
 LLDP-MED) from lldpd, limits their PoE port to it, and advertises the
 allocated power back. Ports with a configured pse_power_limit keep it.
 Needs a PSE driver with the per-port power_limit_class file.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/pse-lldp/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/usr/sbin/pse-lldp $(1)/usr/sbin/pse-lldp
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/pse-lldp $(1)/etc/init.d/pse-lldp
endef

$(eval $(call BuildPackage,pse-lldp))
