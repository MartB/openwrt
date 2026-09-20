include $(TOPDIR)/rules.mk

PKG_NAME:=lldpd-port-labels
PKG_VERSION:=1
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0-or-later
PKG_MAINTAINER:=Martin <martin@familie-boeh.de>

include $(INCLUDE_DIR)/package.mk

define Package/lldpd-port-labels
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=Advertise LuCI switch port labels over LLDP
  DEPENDS:=+lldpd
  PKGARCH:=all
endef

define Package/lldpd-port-labels/description
 Turns the port labels set on LuCI's VLAN Switch page into LLDP port
 descriptions, so neighbours see a name instead of lan1..lanN. Regenerates
 on a procd config trigger when the labels change.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/lldpd-port-labels/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/usr/sbin/lldpd-port-labels $(1)/usr/sbin/lldpd-port-labels
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/lldpd-port-labels $(1)/etc/init.d/lldpd-port-labels
endef

$(eval $(call BuildPackage,lldpd-port-labels))
