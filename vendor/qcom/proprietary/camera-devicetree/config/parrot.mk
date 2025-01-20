dtbo-$(CONFIG_ARCH_PARROT) := parrot-camera.dtbo
#dtbo-$(CONFIG_ARCH_PARROT) += parrot-camera-sensor-idp.dtbo
#dtbo-$(CONFIG_ARCH_PARROT) += parrot-camera-sensor-qrd.dtbo
##############################################################################
dtbo-$(CONFIG_ARCH_PARROT) += oplus/milkywayS3-24263-camera-parrot-overlay.dtbo
dtbo-$(CONFIG_ARCH_PARROT) += oplus/alphaM-24055-camera-parrot-overlay.dtbo
dtbo-$(CONFIG_ARCH_PARROT) += oplus/alphaM-24279-camera-parrot-overlay.dtbo
###############################################################################

dtbo-$(CONFIG_ARCH_RAVELIN) += raveline-camera.dtbo
dtbo-$(CONFIG_ARCH_RAVELIN) += raveline-camera-sensor-idp.dtbo
dtbo-$(CONFIG_ARCH_RAVELIN) += raveline-camera-sensor-qrd.dtbo
dtbo-$(CONFIG_ARCH_RAVELIN) += raveline-camera-sensor-iot.dtbo
