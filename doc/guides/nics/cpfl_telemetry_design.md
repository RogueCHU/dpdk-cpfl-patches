# IPU控制面细粒度遥测实施方案

## 基于CPFL驱动的具体实现设计

> 本文档基于对 `drivers/net/cpfl/` 现有代码的分析，给出在DPDK控制面程序中实现
> "不同Window配置不同队列/lcore"的细粒度遥测方案的具体实施路径。

---

## 1. 现有架构分析

### 1.1 控制队列（Config Queue）现状

CPFL驱动已经具备**16对TX/RX控制队列**（共32条），定义于 `cpfl_ethdev.h`：

```c
#define CPFL_RX_CFGQ_NUM    16
#define CPFL_TX_CFGQ_NUM    16
#define CPFL_CFGQ_NUM       32

struct cpfl_adapter_ext {
    struct idpf_ctlq_info *ctlqp[CPFL_CFGQ_NUM];       // 32条ctlq指针
    struct idpf_ctlq_create_info cfgq_info[CPFL_CFGQ_NUM]; // 配置信息
};
```

**编号规则**（`cpfl_vchnl.c`）：
- 偶数索引 `ctlqp[0], ctlqp[2], ... ctlqp[30]`  → TX控制队列
- 奇数索引 `ctlqp[1], ctlqp[3], ... ctlqp[31]`  → RX控制队列

**当前vport到队列的映射**（`cpfl_flow_engine_fxp.c`）：
```c
cpq_id = vport->base.devarg_id * 2;   // 每个vport绑定固定的控制队列对
cpfl_rule_update(hw, ad->ctlqp[cpq_id], ...);
```

这意味着**已有多队列并行处理规则的基础设施**——只需将4个Window映射到4个专属队列对。

### 1.2 TIME_SEL硬件接口现状

`icpf_rules.h` 已完整定义了TIME_SEL的硬件字段：

```c
#define MEV_RULE_TIME_SEL_S       13       // bit[14:13]，2bit，支持4个老化档位
#define MEV_RULE_TIME_SEL_VAL_S   15       // bit[15]，有效位

struct icpf_rule_cfg_data_common {
    uint8_t  time_sel;         // TIME_SEL值 (0-3)
    uint8_t  time_sel_val;     // 1=TIME_SEL字段有效
};
```

`icpf_rules.c` 中的 `icpf_prep_rule_desc_common_ctx()` 已在SEM/LEM规则下发时
自动填入 `TIME_SEL` 字段。**无需新增硬件通路，直接复用即可。**

### 1.3 轮询机制现状

`cpfl_ethdev.c` 使用 `rte_eal_alarm` 定时回调：
```c
#define CPFL_ALARM_INTERVAL  50000   // 50ms

static void cpfl_dev_alarm_handler(void *param) {
    cpfl_handle_virtchnl_msg(adapter);  // 处理控制消息
    rte_eal_alarm_set(CPFL_ALARM_INTERVAL, cpfl_dev_alarm_handler, adapter);
}
```

此机制可以扩展为遥测通知的处理入口。

---

## 2. Window到队列/lcore的映射方案

### 2.1 队列分配

将16对控制队列中的4对**静态绑定**到4个Window：

| Window   | 用途                | TX队列索引 | RX队列索引 | 对应ctlqp    |
|----------|---------------------|-----------|-----------|--------------|
| Window 0 | 确定性重要流（vMotion等） | `ctlqp[0]` | `ctlqp[1]` | cfgq pair 0 |
| Window 1 | 潜在重要流（80/443等）   | `ctlqp[2]` | `ctlqp[3]` | cfgq pair 1 |
| Window 2 | 普通流                 | `ctlqp[4]` | `ctlqp[5]` | cfgq pair 2 |
| Window 3 | 闲置流候选             | `ctlqp[6]` | `ctlqp[7]` | cfgq pair 3 |

剩余12对队列（cfgq pair 4-15）保留给现有vport规则下发使用，**完全不影响现有流程**。

具体实现：在 `cpfl_ethdev.h` 中新增宏定义：

```c
/* 遥测Window专用的控制队列索引 */
#define CPFL_TELEM_WIN0_TX_CFGQ   0    /* ctlqp[0] */
#define CPFL_TELEM_WIN0_RX_CFGQ   1    /* ctlqp[1] */
#define CPFL_TELEM_WIN1_TX_CFGQ   2
#define CPFL_TELEM_WIN1_RX_CFGQ   3
#define CPFL_TELEM_WIN2_TX_CFGQ   4
#define CPFL_TELEM_WIN2_RX_CFGQ   5
#define CPFL_TELEM_WIN3_TX_CFGQ   6
#define CPFL_TELEM_WIN3_RX_CFGQ   7

/* vport规则下发使用cfgq pair 4起始，避免与遥测冲突 */
#define CPFL_VPORT_CFGQ_BASE      8
```

### 2.2 Lcore分配策略

利用DPDK的 `rte_eal_remote_launch()` 或 **Service Core** 机制，将不同Window的
通知包处理绑定到不同lcore：

```
┌─────────────────────────────────────────────────────────────┐
│                    DPDK EAL lcores                          │
│                                                             │
│  lcore 0 (main)    ─── 主控/管理/DPDK telemetry socket     │
│  lcore 1 (worker)  ─── Window 0 通知处理（核心遥测lcore）    │
│  lcore 2 (worker)  ─── Window 1+2 聚合统计                  │
│  lcore 3 (worker)  ─── TIME_SEL 批量回写 + Age-Counter刷新  │
│  lcore 4+ (worker) ─── 数据面转发                           │
└─────────────────────────────────────────────────────────────┘
```

**关键设计决策**：

- **Window 0 独占lcore 1**：该窗口承载确定性重要流（vMotion等），需要1s级
  感知延迟，独占一个lcore保证处理时效。其轮询循环仅从 `ctlqp[1]`（RX cfgq 0）
  接收通知包，处理量≤2000pps，lcore利用率极低（<4%）。

- **Window 1+2 共享lcore 2**：这两个窗口仅需聚合计数，不做逐流解析。一个
  lcore即可处理3000pps的通知包，仅更新全局统计计数器。

- **Window 3 无lcore分配**：硬件侧已禁用通知（`CNTR_NOTIF_DIS=1`），不会
  产生通知包，无需消耗ARM算力。

- **lcore 3 专职回写**：独立lcore负责通过TX控制队列（`ctlqp[0]`）批量下发
  `Filter Modify` 命令，修改流的TIME_SEL字段并清零Age-Counter，避免与接收
  通知的lcore产生资源竞争。

### 2.3 具体的lcore工作函数

**方式一：使用 `rte_eal_remote_launch()`**

```c
#define CPFL_TELEM_BATCH_SIZE       100    /* max notifications per batch  */
#define CPFL_TELEM_BATCH_WINDOW_US  1000   /* 1 ms batch window            */

/* Window 0 notification handler, runs on dedicated lcore 1 */
static int
cpfl_telem_win0_loop(void *arg)
{
    struct cpfl_adapter_ext *adapter = arg;
    struct idpf_hw *hw = &adapter->base.hw;
    struct idpf_ctlq_msg ctlq_msgs[CPFL_TELEM_BATCH_SIZE];
    uint16_t recv_cnt;

    while (!adapter->telem_stop) {
        recv_cnt = CPFL_TELEM_BATCH_SIZE;
        /* 从Window 0专用RX队列接收通知包 */
        int ret = idpf_ctlq_recv(adapter->ctlqp[CPFL_TELEM_WIN0_RX_CFGQ],
                                 &recv_cnt, ctlq_msgs);
        if (ret == 0 && recv_cnt > 0) {
            /* 批量解析：提取counter_id, pkt_count, flow_id */
            cpfl_telem_process_win0_batch(adapter, ctlq_msgs, recv_cnt);
        }
        /* 1ms批量窗口 —— 避免busy-polling过度消耗CPU */
        rte_delay_us_sleep(CPFL_TELEM_BATCH_WINDOW_US);
    }
    return 0;
}

/* 启动遥测处理线程 */
rte_eal_remote_launch(cpfl_telem_win0_loop, adapter, TELEM_WIN0_LCORE_ID);
```

**方式二：使用 DPDK Service Core（推荐）**

Service Core 更灵活，支持动态绑定/解绑，且多个服务可共享一个lcore：

```c
/* 注册为DPDK service */
struct rte_service_spec telem_win0_service = {
    .name = "cpfl_telem_win0",
    .callback = cpfl_telem_win0_callback,
    .callback_userdata = adapter,
};
rte_service_component_register(&telem_win0_service, &service_id);
rte_service_map_lcore_set(service_id, lcore_id, 1);  /* 绑定到指定lcore */
rte_service_runstate_set(service_id, 1);              /* 启动服务 */
```

---

## 3. 通知包收发的具体数据通路

### 3.1 通知包接收路径

```
硬件Age-Scanner/统计引擎
    │
    ▼  通知包（含counter_id, pkt_count, flow_id, win_id）
Window 0 ──► ctlqp[1] (RX cfgq 0) ──► lcore 1 处理
Window 1 ──► ctlqp[3] (RX cfgq 1) ──► lcore 2 聚合统计
Window 2 ──► ctlqp[5] (RX cfgq 2) ──► lcore 2 聚合统计
Window 3 ──► (通知禁用，无数据流)
```

接收使用IDPF标准API：
```c
int idpf_ctlq_recv(struct idpf_ctlq_info *cq,   // 对应窗口的RX队列
                   u16 *num_q_msg,               // 输入/输出：消息数量
                   struct idpf_ctlq_msg *q_msg); // 输出：消息数组
```

### 3.2 TIME_SEL回写路径（Filter Modify）

```
lcore 3 (回写线程)
    │
    ▼  构造Filter Modify命令
    icpf_fill_rule_cfg_data_common(
        opc = icpf_ctlq_sem_update_rule,
        time_sel = CPFL_TELEM_TIME_SEL_MAX,  // 值=3，对应~2小时
        time_sel_val = 1,                     // 使能TIME_SEL字段
        ...
    )
    │
    ▼  打包为控制队列消息
    icpf_prep_rule_desc(&cfg_data, &ctlq_msg)
    │
    ▼  通过Window 0的TX队列下发
    idpf_ctlq_send(hw, adapter->ctlqp[CPFL_TELEM_WIN0_TX_CFGQ],
                   num_msgs, msgs, wait_count)
```

**此路径100%复用现有代码**，仅需在调用 `icpf_fill_rule_cfg_data_common()` 时
设置正确的 `time_sel` 和 `time_sel_val` 参数：
- `time_sel = 3`：最长老化档位（~2小时，参见Intel IPU E2100文档 §11.26 Flow Aging中
  TIME_SEL 2-bit字段定义，4个档位对应不同老化周期，具体值取决于硬件Profile配置）
- `time_sel_val = 1`：告诉硬件本次更新包含TIME_SEL字段修改

---

## 4. 新增数据结构设计

### 4.1 遥测上下文（嵌入 `cpfl_adapter_ext`）

```c
/* 新增文件: cpfl_telemetry.h */

struct cpfl_telem_flow_entry {
    uint32_t flow_id;            /* 硬件flow ID */
    uint32_t counter_id;         /* 关联的counter ID（高2bit=窗口ID） */
    uint64_t last_pkt_count;     /* 上次采样的累计包计数 */
    uint8_t  silent_count;       /* 连续低增量次数 */
    bool     is_silent;          /* 是否已被软件静默屏蔽 */
    bool     is_protected;       /* 是否已提升TIME_SEL */
    uint64_t active_since_sec;   /* 首次发现时间 */
    uint64_t last_refresh_sec;   /* 上次清零Age-Counter时间 */
    uint8_t  time_sel;           /* 当前TIME_SEL值 (0-3) */
};

struct cpfl_telemetry_ctx {
    struct cpfl_telem_flow_entry *flows;  /* Window 0活跃度表 */
    uint32_t flow_count;                  /* 当前跟踪流数量 */
    rte_spinlock_t flow_lock;             /* 保护flows表的自旋锁 */

    /* 统计计数器 */
    uint64_t total_notif;                 /* 全部窗口通知总数 */
    uint64_t win_notif[4];               /* 各窗口通知计数 */
    uint32_t protected_cnt;              /* 当前受保护流数量 */

    /* 控制标志 */
    volatile bool stop;                   /* 停止信号 */
    bool initialized;

    /* lcore/service绑定信息 */
    uint32_t win0_lcore_id;              /* Window 0处理lcore */
    uint32_t aggregate_lcore_id;         /* Window 1+2聚合lcore */
    uint32_t writeback_lcore_id;         /* TIME_SEL回写lcore */
};
```

在 `cpfl_adapter_ext` 中新增一个指针：
```c
struct cpfl_adapter_ext {
    /* ... 现有字段 ... */
    struct cpfl_telemetry_ctx *telem_ctx;   /* 新增 */
};
```

### 4.2 窗口配置结构

```c
struct cpfl_telem_win_cfg {
    uint8_t  win_id;             /* 0-3 */
    uint8_t  cnt_grow_n;         /* CNT_GROW_N 包增量阈值指数 */
    uint16_t timeout_sec;        /* TIMEOUT 定时上报周期 */
    bool     notif_enabled;      /* CNTR_NOTIF_DIS取反 */
    uint32_t rate_limit_pps;     /* 令牌桶限速 */
    uint32_t max_burst;          /* 最大突发 */
    uint8_t  tx_cfgq_idx;        /* 绑定的TX控制队列索引 */
    uint8_t  rx_cfgq_idx;        /* 绑定的RX控制队列索引 */
};
```

---

## 5. 初始化与生命周期管理

### 5.1 初始化流程（嵌入 `cpfl_adapter_ext_init()`）

在现有初始化链中，在 `cpfl_tdi_init()` 之后插入遥测初始化：

```c
/* cpfl_ethdev.c: cpfl_adapter_ext_init() */

ret = cpfl_tdi_init(adapter);
if (ret) goto err_tdi_init;

/* 新增：遥测模块初始化 */
ret = cpfl_telemetry_init(adapter);
if (ret) goto err_telem_init;

/* ... */

err_telem_init:
    cpfl_tdi_uninit(adapter);
err_tdi_init:
    /* ... */
```

`cpfl_telemetry_init()` 内部需执行：

1. 分配 `cpfl_telemetry_ctx` 结构及 `flows` 数组
2. 初始化自旋锁
3. **不修改硬件**——Window参数、CNE_CFG等全局寄存器在系统更底层的firmware/BSP中完成
4. 注册DPDK telemetry命令（`/cpfl/telemetry/summary` 等）
5. 启动 lcore 工作函数或注册 Service Core

### 5.2 清理流程（嵌入 `cpfl_adapter_ext_deinit()`）

```c
/* cpfl_ethdev.c: cpfl_adapter_ext_deinit() */

cpfl_telemetry_uninit(adapter);   /* 新增：在tdi_uninit之前 */
cpfl_tdi_uninit(adapter);
cpfl_flow_uninit(adapter);
/* ... */
```

`cpfl_telemetry_uninit()` 内部需执行：

1. 设置 `ctx->stop = true`，等待各lcore退出
2. 释放 `flows` 数组和 `ctx` 结构

### 5.3 DPDK Telemetry命令注册

使用 `RTE_INIT` 宏注册遥测命令，与cnxk等驱动保持一致：

```c
RTE_INIT(cpfl_telemetry_register_cmds)
{
    rte_telemetry_register_cmd("/cpfl/telemetry/summary",
        cpfl_telem_handle_summary,
        "Returns IPU telemetry notification summary");
    rte_telemetry_register_cmd("/cpfl/telemetry/window_cfg",
        cpfl_telem_handle_win_cfg,
        "Returns per-window telemetry configuration");
    rte_telemetry_register_cmd("/cpfl/telemetry/protected_flows",
        cpfl_telem_handle_protected,
        "Returns list of TIME_SEL-protected flow IDs");
}
```

运行时通过 `dpdk-telemetry.py` 连接查询：
```bash
$ dpdk-telemetry.py
--> /cpfl/telemetry/summary
{
  "total_notifications": 45230,
  "win0_notifications": 1820,
  "tracked_flows": 1250,
  "protected_flows": 87
}
```

---

## 6. 核心处理逻辑

### 6.1 Window 0通知处理（lcore 1）

```
接收通知包（批量，每1ms或100包一批）
    │
    ├─ 解析 counter_id → 提取 win_id = counter_id >> 22
    │
    ├─ 在flows表中查找 flow_id
    │   ├─ 不存在 → 新建条目，记录初始pkt_count
    │   └─ 存在 → 计算 pkt_increment = 当前pkt_count - 上次pkt_count
    │
    ├─ 静默流检测
    │   ├─ 已静默 且 increment < 4096 → 跳过（节省CPU）
    │   ├─ 已静默 且 increment ≥ 4096 → 解除静默
    │   ├─ 未静默 且 increment < 500  → silent_count++
    │   │   └─ silent_count ≥ 3 → 标记为静默
    │   └─ 未静默 且 increment ≥ 500  → silent_count = 0
    │
    └─ 重要会话识别
        ├─ increment ≥ 10000 且 连续2次 → 确认需保护
        ├─ 活跃时长 ≥ 30s              → 确认需保护
        └─ 确认后 → 将{flow_id, time_sel=3}放入回写队列
```

### 6.2 TIME_SEL回写（lcore 3）

```
从回写队列读取待处理flows
    │
    ├─ 批量构造Filter Modify命令（复用icpf_rules.h API）
    │   struct icpf_rule_cfg_data cfg_data;
    │   icpf_fill_rule_cfg_data_common(
    │       icpf_ctlq_sem_update_rule,  // Update操作
    │       cookie, vsi_id, port_num, host_id,
    │       3,   /* time_sel = TIME_SEL_MAX (~2h, see §11.26 Flow Aging) */
    │       1,   /* time_sel_val = valid */
    │       0, 2, payload_len, payload, &cfg_data.common);
    │   icpf_prep_rule_desc(&cfg_data, &ctlq_msg);
    │
    ├─ 通过TX控制队列下发
    │   idpf_ctlq_send(hw, adapter->ctlqp[CPFL_TELEM_WIN0_TX_CFGQ], ...)
    │
    └─ 定期刷新（每30分钟）
        └─ 对所有is_protected流重新清零Age-Counter
```

### 6.3 Window 1+2聚合统计（lcore 2）

```
接收通知包（从ctlqp[3]和ctlqp[5]）
    │
    └─ 仅更新全局统计计数器
        ctx->win_notif[1] += recv_cnt;
        ctx->win_notif[2] += recv_cnt;
        /* 不做逐流解析 */
```

---

## 7. 需新增/修改的文件清单

| 文件 | 操作 | 内容 |
|------|------|------|
| `drivers/net/cpfl/cpfl_telemetry.h` | **新增** | 数据结构定义、常量、API声明 |
| `drivers/net/cpfl/cpfl_telemetry.c` | **新增** | 初始化/清理、通知处理、TIME_SEL回写、telemetry命令回调、lcore工作函数 |
| `drivers/net/cpfl/meson.build` | **修改** | `sources` 列表添加 `cpfl_telemetry.c`；`deps` 添加 `telemetry` |
| `drivers/net/cpfl/cpfl_ethdev.h` | **修改** | `cpfl_adapter_ext` 新增 `telem_ctx` 指针；include `cpfl_telemetry.h` |
| `drivers/net/cpfl/cpfl_ethdev.c` | **修改** | `cpfl_adapter_ext_init()` 中调用 `cpfl_telemetry_init()`；`cpfl_adapter_ext_deinit()` 中调用 `cpfl_telemetry_uninit()` |

---

## 8. 与原设计方案的对应关系

| 设计方案章节 | CPFL实现位置 | 关键DPDK/CPFL API |
|-------------|-------------|-------------------|
| §3.1 静态窗口划分 | 队列分配宏 + `cpfl_telem_win_cfg` 结构 | `ctlqp[]` 数组索引 |
| §3.2 硬件参数配置 | firmware/BSP层（DPDK层不直接写寄存器） | — |
| §3.3 硬件粗粒度过滤 | 硬件自动执行（配置在初始化时下发） | — |
| §4.1 核心窗口聚焦 | `cpfl_telem_win0_loop` 仅处理ctlqp[1] | `idpf_ctlq_recv()` |
| §4.2 静默流屏蔽 | `cpfl_telem_flow_entry.silent_count` | 纯软件逻辑 |
| §4.3 批量异步解析 | 1ms/100包批量窗口 | `rte_delay_us_sleep()` |
| §4.4 重要会话识别 | `flow_qualifies_for_protection()` | 纯软件逻辑 |
| §4.5 TIME_SEL回写 | `icpf_fill_rule_cfg_data_common(time_sel=3)` | `icpf_prep_rule_desc()` → `idpf_ctlq_send()` |
| §5 DPDK Telemetry | `RTE_INIT(cpfl_telemetry_register_cmds)` | `rte_telemetry_register_cmd()` |

---

## 9. 性能估算

| 指标 | 值 | 说明 |
|------|----|------|
| lcore 1 (Window 0) CPU利用率 | ≤4% | 2000pps × 简单解析（基于1GHz ARM核心估算，实际取决于目标平台） |
| lcore 2 (Window 1+2) CPU利用率 | ≤3% | 3000pps × 仅计数 |
| lcore 3 (回写) CPU利用率 | ≤1% | 低频批量操作 |
| 回写延迟 | <10ms | 批量Filter Modify，硬件即时生效 |
| 重要流识别延迟 | ≤1s | Window 0的1s定时上报 |
| flows表内存占用 | ~1.5MB | 25000 × 64B per entry |
