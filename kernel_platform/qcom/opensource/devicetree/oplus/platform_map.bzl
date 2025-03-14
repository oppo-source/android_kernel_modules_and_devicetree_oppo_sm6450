_platform_map = {
    "parrot": {
        "dtb_list": [
            {"name": "parrot.dtb"},
        ],
        "dtbo_list": [
            {"name": "milkyways35g-24263-parrot-overlay.dtbo"},
            {"name": "milkyways35g-24263-parrot-export-overlay.dtbo"},
            {"name": "milkyways35g-24264-parrot-overlay.dtbo"},
            {"name": "alpham-24055-parrot-overlay.dtbo"},
            {"name": "alpham-24279-parrot-overlay.dtbo"},
        ],
    },
    "sun": {
        "dtb_list": [

        ],
        "dtbo_list": [

        ],
    },
    "tuna": {
        "dtb_list": [

        ],
        "dtbo_list": [

        ],
    },
    "kera": {
        "dtb_list": [

        ],
        "dtbo_list": [

        ],
    },
    "sun-tuivm": {
        "dtb_list": [

        ],
    },
    "sun-oemvm": {
        "dtb_list": [

        ],
    },
    "pineapple": {
        "dtb_list": [

        ],
        "dtbo_list": [

        ],
    },
    "pineapple-tuivm": {
        "dtb_list": [

        ],
    },
    "pineapple-oemvm": {
        "dtb_list": [

        ],
    },
    "monaco": {
        "dtb_list": [

        ],
        "dtbo_list": [
        ],
    },
    "sdxkova": {
         "dtb_list": [

          ],
         "dtbo_list": [

         ],
   },
    "sdxkova.cpe.wkk": {
        "dtb_list": [

        ],
        "dtbo_list": [

        ],
    },
    "parrot-tuivm": {
        "dtb_list": [

        ],
    },
}

def _get_dtb_lists(target, dt_overlay_supported):
    if not target in _platform_map:
        fail("{} not in device tree platform map!".format(target))

    ret = {
        "dtb_list": [],
        "dtbo_list": [],
    }

    for dtb_node in [target] + _platform_map[target].get("binary_compatible_with", []):
        ret["dtb_list"].extend(_platform_map[dtb_node].get("dtb_list", []))
        if dt_overlay_supported:
            ret["dtbo_list"].extend(_platform_map[dtb_node].get("dtbo_list", []))
        else:
            # Translate the dtbo list into dtbs we can append to main dtb_list
            for dtb in _platform_map[dtb_node].get("dtb_list", []):
                dtb_base = dtb["name"].replace(".dtb", "")
                for dtbo in _platform_map[dtb_node].get("dtbo_list", []):
                    if not dtbo.get("apq", True) and dtb.get("apq", False):
                        continue

                    dtbo_base = dtbo["name"].replace(".dtbo", "")
                    ret["dtb_list"].append({"name": "{}-{}.dtb".format(dtb_base, dtbo_base)})

    return ret

def get_dtb_list(target, dt_overlay_supported = True):
    return [dtb["name"] for dtb in _get_dtb_lists(target, dt_overlay_supported).get("dtb_list", [])]

def get_dtbo_list(target, dt_overlay_supported = True):
    return [dtb["name"] for dtb in _get_dtb_lists(target, dt_overlay_supported).get("dtbo_list", [])]
