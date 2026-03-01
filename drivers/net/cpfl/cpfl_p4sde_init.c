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

#include <dlfcn.h>
#include "cpfl_p4sde_init.h"

#ifdef RTE_FLOW_SHIM
#include <rte_flow_shim_flow.h>

#define RTE_FLOW_SHIM_LIB "librte_flow_shim.so"
#define RTE_FLOW_SHIM_OPS_INIT "rte_flow_shim_init_dpdk_fps"
void *rte_flow_shim_lib_hdl = NULL;
void (*p_rte_flow_shim_init_dpdk_fps)(struct rte_flow_ops *);
struct rte_flow_ops shim_flow_ops;

int (*p_rte_flow_shim_conf_lib_init)(char *);
struct tdi_ops_t *p_rfs_tdi_ops;
struct tdi_ops_t rfs_tdi_ops;
void (*tdi_ops_init_p)(struct tdi_ops_t *);
void (*p_rfs_set_perf_status)(bool);

bool is_rte_flow_shim = false;
#endif

#ifdef IS_CPF_PMD_ENABLED
void (*p_bf_switchd_parse_options_cb)(char *);
void (*p_bf_switchd_lib_init_cb)(bool);
void (*p_bf_switchd_exit_cb)(void);

bool is_bf_switchd = false;

static void load_bf_switchd_lib_sym(void)
{
	void *bf_switchd_lib_hdl;
	char *error;

	bf_switchd_lib_hdl = dlopen(BF_SWITCHD_LIB, RTLD_LOCAL | RTLD_LAZY);
	if (!bf_switchd_lib_hdl) {
		printf("Unable to load %s lib : %s\n", BF_SWITCHD_LIB,  dlerror());
		return;
	}
	dlerror();
	*(void **)(&p_bf_switchd_parse_options_cb) = dlsym(bf_switchd_lib_hdl, BF_SWITCHD_PARSE_OPTIONS);
	if ((error = dlerror()) != NULL)  {
		printf("Unable to load %s lib : %s\n", BF_SWITCHD_PARSE_OPTIONS,  dlerror());
		fputs(error, stderr);
		return;
	}

	*(void **)(&p_bf_switchd_lib_init_cb) = dlsym(bf_switchd_lib_hdl, BF_SWITCHD_LIB_INIT);
	if ((error = dlerror()) != NULL)  {
		printf("Unable to load %s lib : %s\n", BF_SWITCHD_LIB_INIT,  dlerror());
		fputs(error, stderr);
		return;
	}

	*(void **)(&p_bf_switchd_exit_cb) = dlsym(bf_switchd_lib_hdl, BF_SWITCHD_EXIT);
	if ((error = dlerror()) != NULL)  {
		printf("Unable to load %s lib : %s\n", BF_SWITCHD_EXIT,  dlerror());
		fputs(error, stderr);
		return;
	}
#ifdef RTE_FLOW_SHIM
	*(void **)(&tdi_ops_init_p) = dlsym(bf_switchd_lib_hdl, TDI_OPS_INIT);
	if ((error = dlerror()) != NULL)  {
		printf("Unable to load %s lib : %s\n", TDI_OPS_INIT,  dlerror());
		fputs(error, stderr);
		return;
	}
#endif
	printf("%s lib loaded successfully\n", BF_SWITCHD_LIB);
}

void cpfl_bf_switchd_lib_init(char *install_path, char *conf_file, bool lock)
{
	char bf_switchd_argv[256];
	char *default_options = "--init-mode=cold --status-port 7777  --background";
	char lockless[16]; 

	memset(bf_switchd_argv,0x0, 256);
	memset(lockless,0x0, 16);
	if (!lock)
		sprintf(lockless,"--lockless");

	sprintf(bf_switchd_argv, "--install-dir=%s --conf-file=%s %s %s",
			install_path, conf_file, default_options, lockless);
	if (is_bf_switchd) {
		load_bf_switchd_lib_sym();
		if (p_bf_switchd_parse_options_cb)
			p_bf_switchd_parse_options_cb(bf_switchd_argv);
		if (p_bf_switchd_lib_init_cb)
			p_bf_switchd_lib_init_cb(true);
	}
}

void bf_switchd_lib_exit(void) {
	if (is_bf_switchd) {
		if (p_bf_switchd_exit_cb)
			p_bf_switchd_exit_cb();
	}
}
#endif

#ifdef RTE_FLOW_SHIM
static void load_rte_flow_shim_lib_dym(void)
{
	char *error;

	rte_flow_shim_lib_hdl = dlopen(RTE_FLOW_SHIM_LIB, RTLD_LOCAL | RTLD_LAZY);
	if (!rte_flow_shim_lib_hdl) {
		printf("Unable to load %s lib : %s\n", RTE_FLOW_SHIM_LIB,  dlerror());
		goto return_null;
	}
	dlerror();
	*(void **)(&p_rte_flow_shim_conf_lib_init) = dlsym(rte_flow_shim_lib_hdl, RTE_FLOW_SHIM_INIT);
	if ((error = dlerror()) != NULL)  {
		printf("Unable to load %s lib : %s\n", RTE_FLOW_SHIM_INIT,  dlerror());
		fputs(error, stderr);
		goto return_null;
	}
	*(void **)(&p_rfs_tdi_ops) = dlsym(rte_flow_shim_lib_hdl, RTE_FLOW_SHIM_TDI_OPS);
	if ((error = dlerror()) != NULL)  {
		printf("Unable to load %s lib : %s\n", RTE_FLOW_SHIM_TDI_OPS,  dlerror());
		fputs(error, stderr);
		goto return_null;
	}
    *(void **)(&p_rte_flow_shim_init_dpdk_fps) = dlsym(rte_flow_shim_lib_hdl, RTE_FLOW_SHIM_OPS_INIT);
    if ((error = dlerror()) != NULL)  {
        printf("Unable to load %s lib : %s\n", RTE_FLOW_SHIM_OPS_INIT,  dlerror());
        fputs(error, stderr);
        goto return_null;
    }
    *(void **)(&p_rfs_set_perf_status) = dlsym(rte_flow_shim_lib_hdl, RTE_FLOW_SHIM_SET_PERF_STATUS);
    if ((error = dlerror()) != NULL)  {
        printf("Unable to load %s lib : %s\n", RTE_FLOW_SHIM_SET_PERF_STATUS ,  dlerror());
        fputs(error, stderr);
        goto return_null;
    }
	printf("%s lib loaded successfully\n", RTE_FLOW_SHIM_LIB);
return_null:
	return;
}

static void unload_rte_flow_shim_lib_dym(void *handle)
{
	if ( handle )
		dlclose(handle);
}

void cpfl_rfs_lib_init(char *rfs_conf){
	if (is_rte_flow_shim) {
		load_rte_flow_shim_lib_dym();

		if (tdi_ops_init_p && p_rfs_tdi_ops)
			tdi_ops_init_p(p_rfs_tdi_ops);

		if (p_rte_flow_shim_conf_lib_init){
			if (p_rte_flow_shim_conf_lib_init(rfs_conf)) {
				fprintf(stderr, "Warning : shim init failed\n");
				rte_exit(EXIT_FAILURE,
						"failed to parse %s \n", rfs_conf);
			}
		}
		if ( p_rte_flow_shim_init_dpdk_fps )
			p_rte_flow_shim_init_dpdk_fps(&shim_flow_ops);
		else
			fprintf(stderr, "Warning : Failed to init shim_flow_ops");

	}
}

void rfs_lib_exit(void) {
	if (is_rte_flow_shim)
		unload_rte_flow_shim_lib_dym(rte_flow_shim_lib_hdl);
}
#endif
