load("//build/kernel/kleaf:kernel.bzl", "ddk_headers")
load("//build/kernel/oplus:oplus_modules_define.bzl", "define_oplus_ddk_module", "bazel_support_platform")
load("//build/kernel/oplus:oplus_modules_dist.bzl", "ddk_copy_to_dist_dir")

def get_platform_specific_files():
    if bazel_support_platform == "qcom":
        return []
    elif bazel_support_platform == "mtk":
        return []
    else:
        return []

def define_oplus_local_modules():

    define_oplus_ddk_module(
        name = "oplus_bsp_sched_ext",
        srcs = native.glob([
            "**/*.h",
        ]),
        conditional_srcs = {},
        local_defines = [],
        includes = ["."],
        ko_deps = [
            "//vendor/oplus/kernel/synchronize:oplus_locking_strategy",
            "//vendor/oplus/kernel/ipc:oplus_binder_strategy",
        ],
        header_deps = [
            "//vendor/oplus/kernel/synchronize:config_headers",
            "//vendor/oplus/kernel/ipc:config_headers",
        ],
        copts = select({
            "//build/kernel/kleaf:kocov_is_true": ["-fprofile-arcs", "-ftest-coverage"],
            "//conditions:default": [],
        }),
    )
    ddk_headers(
        name = "config_headers",
        hdrs  = native.glob([
            "**/*.h",
        ]),
        includes = ["."],
    )
    ddk_copy_to_dist_dir(
        name = "oplus_bsp_sched_ext",
        module_list = [
            "oplus_bsp_sched_ext",
        ],
    )
