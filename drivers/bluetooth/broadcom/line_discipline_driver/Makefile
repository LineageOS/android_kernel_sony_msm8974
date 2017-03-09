brcm_hci_ldisc-objs := brcm_hci.o brcm_sh_ldisc.o brcm_bluesleep.o
obj-$(CONFIG_LINE_DISCIPLINE_DRIVER) := brcm_hci_ldisc.o
ccflags-y += -w -DVERSION="\"1.2\""
ifneq ($(CONFIG_SOMC_SHINANO_LPM),)
  ccflags-y += -DCONFIG_SOMC_SHINANO_LPM=$(CONFIG_SOMC_SHINANO_LPM)
endif
