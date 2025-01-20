PARROT_BASE_DTB += ../qcom/parrot.dtb

OPLUS_PARROT_BOARDS += milkyways35g-24263-parrot-overlay.dtbo\
                       milkyways35g-24263-parrot-export-overlay.dtbo\
                       milkyways35g-24264-parrot-overlay.dtbo\
                       alpham-24279-parrot-overlay.dtbo\
                       alpham-24055-parrot-overlay.dtbo


dtb-y += $(OPLUS_PARROT_BOARDS) $(PARROT_BASE_DTB)

always-y        := $(dtb-y)
subdir-y        := $(dts-dirs)
clean-files     := *.dtb *.dtbo
