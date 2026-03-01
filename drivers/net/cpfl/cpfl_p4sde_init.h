/*
 * Copyright(c) 2023 Intel Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef CPFL_P4SDE_INIT_H
#define CPFL_P4SDE_INIT_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef RTE_FLOW_SHIM
#include <shim_tdi_api.h>
#endif

#ifdef IS_CPF_PMD_ENABLED
#define BF_SWITCHD_PARAMS_MAX 256
#define BF_SWITCHD_CONF "bfswitchd_conf"
#define BF_SWITCHD_INSTALL_PATH "bfswitchd_install"
#define BF_SWITCHD_LOCK "bfswitchd_lock"
#define BF_SWITCHD_LIB_INIT "tdi_lib_init"
#define BF_SWITCHD_EXIT "tdi_switchd_exit"
#define BF_SWITCHD_PARSE_OPTIONS "tdi_config_init"
#define BF_SWITCHD_LIB "libbf_switchd_lib.so"

extern bool is_bf_switchd;
extern char *bf_switchd_argv;
extern void (*p_bf_switchd_parse_options_cb)(char *);
extern void (*p_bf_switchd_lib_init_cb)(bool);
extern void (*p_bf_switchd_exit_cb)(void);

void cpfl_bf_switchd_lib_init(char *install_path, char *conf_file, bool lock);
void bf_switchd_lib_exit(void);
#endif

#ifdef RTE_FLOW_SHIM
#define RFS_CONF_FILE_NAME_MAX 100
#define RFS_CONF_FILE "rfs_conf"
#define TDI_OPS_INIT "tdi_rte_shim_ops_init"
#define RTE_FLOW_SHIM_LIB "librte_flow_shim.so"
#define RTE_FLOW_SHIM_INIT "rte_flow_shim_conf_lib_init"
#define RTE_FLOW_SHIM_SET_P4_NAME "set_p4_program_name"
#define RTE_FLOW_SHIM_TDI_OPS "rfs_tdi_ops"
#define RTE_FLOW_SHIM_SET_PERF_STATUS "rfs_set_perf_status"

extern bool is_rte_flow_shim;
extern int (*p_rte_flow_shim_conf_lib_init)(char *);
extern struct tdi_ops_t *p_rfs_tdi_ops;
extern void (*tdi_ops_init_p)(struct tdi_ops_t *);
extern struct rte_flow_ops shim_flow_ops;
extern void (*p_rte_flow_shim_init_dpdk_fps)(struct rte_flow_ops *);
extern void (*p_rfs_set_perf_status)(bool);

void cpfl_rfs_lib_init(char *);
void rfs_lib_exit(void);
#endif

#endif
