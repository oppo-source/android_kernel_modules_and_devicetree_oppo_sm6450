# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2023-2030 Oplus. All rights reserved.

KBUILD_OPTIONS += CONFIG_OPLUS_FEATURE_POWER_HOOK=m

KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build
M ?= $(shell pwd)
modules modules_install clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) $(KBUILD_OPTIONS) $(@)
