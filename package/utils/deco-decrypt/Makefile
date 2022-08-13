# SPDX-License-Identifier: GPL-2.0-or-later

include $(TOPDIR)/rules.mk

PKG_NAME:=deco-decrypt
PKG_RELEASE:=1

PKG_FLAGS:=nonshared
PKG_LICENSE:=GPL-2.0-or-later
PKG_CONFIG_DEPENDS:=\
	CONFIG_DECO_DECRYPT_OPENSSL \
	CONFIG_DECO_DECRYPT_WOLFSSL

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

CMAKE_INSTALL:=1
CMAKE_OPTIONS+=$(if $(CONFIG_DECO_DECRYPT_WOLFSSL),-DUSE_WOLFSSL=1)

define Package/deco-decrypt
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Decryption utility for TP-Link Deco S4
  DEPENDS:=@TARGET_ath79_generic_DEVICE_tplink_deco-s4-v2 +DECO_DECRYPT_WOLFSSL:libwolfssl +DECO_DECRYPT_OPENSSL:libopenssl
endef

define Package/deco-decrypt/description
  This is a small DES decryption program to decrypt
  mtd confiuration partitions found on TP-Link Deco
  S4 routers
endef

define Package/deco-decrypt/config
  if PACKAGE_deco-decrypt
    choice
	prompt "Crypto provider"
	default DECO_DECRYPT_WOLFSSL

	config DECO_DECRYPT_OPENSSL
	bool "OpenSSL"

	config DECO_DECRYPT_WOLFSSL
	bool "wolfSSL"
    endchoice
  endif
endef

define Package/deco-decrypt/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/deco_decrypt $(1)/usr/bin
endef

$(eval $(call BuildPackage,deco-decrypt))
