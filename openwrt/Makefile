include $(TOPDIR)/rules.mk

PKG_NAME:=pkt-frag
PKG_VERSION:=2.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk

define KernelPackage/pkt-frag
  SUBMENU:=Network Support
  TITLE:=Advanced packet manipulation for DPI bypass
  FILES:=$(PKG_BUILD_DIR)/pkt_frag.$(LINUX_KMOD_SUFFIX)
  AUTOLOAD:=$(call AutoLoad,30,pkt_frag)
  KCONFIG:=
endef

define KernelPackage/pkt-frag/description
  Kernel module for DPI bypass: IP fragmentation, TLS ClientHello splitting,
  QUIC/HTTP3 fragmentation, random padding, TLS fingerprint modification.
  Supports IPv4/IPv6, TCP/UDP.
endef

define Package/pkt-frag-daemon
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Packet fragmentation management daemon
  DEPENDS:=+kmod-pkt-frag +libuci +libjson-c +libpthread
endef

define Package/pkt-frag-daemon/description
  Userspace daemon to manage packet fragmentation module parameters via UCI.
  Supports config reload, fingerprint rotation, state persistence.
endef

define Package/luci-app-pkt-frag
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI support for pkt-frag
  DEPENDS:=+pkt-frag-daemon +luci-base +luci-compat
  PKGARCH:=all
endef

define Package/luci-app-pkt-frag/description
  Web interface for configuring advanced packet fragmentation and DPI bypass.
endef

EXTRA_KCONFIG:= \
	CONFIG_PKT_FRAG=m

EXTRA_CFLAGS:= \
	-I$(PKG_BUILD_DIR)

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./pkt_frag.c $(PKG_BUILD_DIR)/
	$(CP) ./pkt-frag-daemon.c $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		SUBDIRS="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		modules
	
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) \
		-o $(PKG_BUILD_DIR)/pkt-frag-daemon \
		$(PKG_BUILD_DIR)/pkt-frag-daemon.c \
		-luci -ljson-c -lpthread
endef

define KernelPackage/pkt-frag/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/etc/config/pkt-frag $(1)/etc/config/pkt-frag
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/pkt-frag $(1)/etc/init.d/pkt-frag
endef

define Package/pkt-frag-daemon/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/pkt-frag-daemon $(1)/usr/sbin/pkt-frag-daemon
endef

define Package/luci-app-pkt-frag/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA) ./luci/controller/pkt-frag.lua $(1)/usr/lib/lua/luci/controller/pkt-frag.lua
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi
	$(INSTALL_DATA) ./luci/model/cbi/pkt-frag.lua $(1)/usr/lib/lua/luci/model/cbi/pkt-frag.lua
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/pkt-frag
	$(INSTALL_DATA) ./luci/view/pkt-frag/status.htm $(1)/usr/lib/lua/luci/view/pkt-frag/status.htm
endef

$(eval $(call KernelPackage,pkt-frag))
$(eval $(call BuildPackage,pkt-frag-daemon))
$(eval $(call BuildPackage,luci-app-pkt-frag))