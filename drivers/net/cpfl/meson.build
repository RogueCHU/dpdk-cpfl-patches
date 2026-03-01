# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 Intel Corporation

if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

deps += ['hash', 'common_idpf']

sources = files(
        'icpf_rules.c',
        'cpfl_ethdev.c',
        'cpfl_flow.c',
        'cpfl_flow_engine.c',
        'cpfl_flow_engine_fxp.c',
        'cpfl_flow_fxp_metadata.c',
        'cpfl_flow_js_parser.c',
        'cpfl_fxp_rule.c',
        'cpfl_rxtx.c',
        'cpfl_representor.c',
        'cpfl_tdi.c',
        'cpfl_tdi_js_parser.c',
        'cpfl_vchnl.c',
        'cpfl_p4sde_api.c',
)
if cc.has_argument('-DRTE_FLOW_SHIM')
sources += files('cpfl_p4sde_init.c')
endif

if arch_subdir == 'x86'
    cpfl_avx512_cpu_support = (
        cc.get_define('__AVX512F__', args: machine_args) != '' and
        cc.get_define('__AVX512BW__', args: machine_args) != '' and
        cc.get_define('__AVX512DQ__', args: machine_args) != ''
    )

    cpfl_avx512_cc_support = (
        not machine_args.contains('-mno-avx512f') and
        cc.has_argument('-mavx512f') and
        cc.has_argument('-mavx512bw') and
        cc.has_argument('-mavx512dq')
    )

    if cpfl_avx512_cpu_support == true or cpfl_avx512_cc_support == true
        cflags += ['-DCC_AVX512_SUPPORT']
    endif
endif

js_dep = dependency('json-c', required: false, method : 'pkg-config')
ext_deps += js_dep

if cc.has_argument('-DRTE_FLOW_SHIM')
includes += include_directories('../../../../../../rte-flow-shim/include')
includes += include_directories('../../../../../../third-party/tdi/third-party/target-syslibs/include/')
includes += include_directories('../../../../../../third-party/tdi/include/')
includes += include_directories('../../../../../../third-party/tdi/third-party/target-utils/third-party/cJSON/')
endif

if cc.has_argument('-DCPCHNL2_SUPPORT')
  cflags += ['-DCPCHNL2_SUPPORT']
endif
headers = files('rte_pmd_idpf.h','rte_pmd_iecm.h')
