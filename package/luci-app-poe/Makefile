#
# LuCI support for PoE on Realtek switches using the kernel PSE-PD framework.
#

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for PoE (PSE-PD)
LUCI_DEPENDS:=+ethtool-full +rpcd-mod-ucode
LUCI_PKGARCH:=all

PKG_LICENSE:=GPL-2.0-or-later
PKG_MAINTAINER:=Martin <martin@familie-boeh.de>

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
