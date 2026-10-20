# Windows 软件加密授权系统设计规范与对接文档

| 项 | 内容 |
| --- | --- |
| 文档性质 | 团队目标规范 + 本仓库实现 + 现网只读探测差异（目标项未实现前不得宣称已符合） |
| 修订基线 | 2026-10-17；以实际部署 commit、配置和实测响应为最终联调基线 |
| 适用范围 | Windows 桌面端（Python / C# / C++ / Electron / Go 等） |
| 对齐基线 | RCC（ControlCommand）、WinPilot、E-Player 三套现网实现 |
| 授权服务 | `c3812600/license-service`（线上入口：`https://licenses.lonk.vip`） |
| 签名算法 | **Ed25519**（唯一选择，不再并列 RSA） |
| 机器码哈希 | **SHA-256**（`fingerprint_ver=2`，废弃 MD5） |
| 授权码格式 | `<APP_PREFIX>.<base64url(payload)>.<base64url(signature)>` |

本文档旨在为 Windows 平台软件提供标准化的加密与授权设计，覆盖：**机器码绑定、Ed25519 签名授权码、DPAPI 冗余存储、防时间回拨、在线/离线激活、试用与过期策略、license-service 对接**。
**阅读约定：**“必须”表示上线目标；“本仓库”指此文件夹中的实现；“现网观察”仅指 2026-10-17 的无鉴权只读探测，不证明生产代码版本及写接口的语义；“目标”尚待实现。附录 H 是 Rust Node 客户端快照，不代表服务端目标接口已上线。开发 AI 应先核对服务端实际部署 commit、允许产品、公钥与环境配置，再按已实现的契约联调；不得仅凭本规范假设接口上线。

**相对初版的主要变更（实施时请以本版为准）：**

1. 机器码改为**精确绑定**，删除「80% 特征向量模糊匹配」（同配机器/镜像环境可被一码多机）。
2. 签名算法**固定 Ed25519**，与现网三端一致；不再提供 RSA 备选。
3. 授权码与 Payload **字节级格式写死**，附录含测试向量。
4. 防时间回拨独立成章：签名状态 + 可信时间源 + 明确状态机。
5. 存储加密规定为 **DPAPI**；ADS 降级为可选，不作为主防删手段。
6. API 与 license-service **现网/目标接口对齐**，区分「已实现」与「待扩展」。
7. 增加公钥轮换、模块划分、测试矩阵、密钥管理等附录。
8. **机器码哈希锁定 SHA-256**，废弃 MD5（WinPilot 已切换并需重签授权）。
9. **机器码稳定性与唯一性成文**：禁止可移动卷参与；DPAPI 缓存防采集偶发跳变；弱路径禁止自动签发付费授权；插拔 U 盘不得失效。
10. **仓库同步**：本仓库支持按产品配置试用上限（`LICENSE_SERVICE_TRIAL_DAYS_MAP`）与请求 `trial_days` 钳制（见 §6.3.1 / §8.1）；新增产品还须同时配置 `LICENSE_SERVICE_ALLOWED_APPS`。公网实际配置须另行核对。

---

## 一、 系统架构概述

整个授权体系由三部分组成：

1. **客户端（Client App）**  
   硬件指纹采集、授权码验签、本地 DPAPI 冗余存储与恢复、防回拨状态、代码混淆保护。
2. **授权服务器（License Server）**  
   基于 `c3812600/license-service`：许可证签发、试用发放、机器绑定/换绑、状态校验、吊销与审计。
3. **许可证（License Token）**  
   由服务端 Ed25519 私钥签发的字符串令牌，内含 `app_name`、`machine_code`、有效期、可选功能模块等字段。

```text
┌─────────────────────┐         ┌──────────────────────────┐
│  Client App         │         │  license-service         │
│  ┌───────────────┐  │  HTTPS  │  ┌────────────────────┐  │
│  │ Machine ID    │──┼─────────┼─▶│ 签发 / 试用 / 换绑  │  │
│  ├───────────────┤  │         │  ├────────────────────┤  │
│  │ Ed25519 Verify│◀─┼─────────┼──│ 公钥分发 / 校验    │  │
│  ├───────────────┤  │         │  ├────────────────────┤  │
│  │ DPAPI Store   │  │         │  │ 吊销 / 审计        │  │
│  │ (file+reg)    │  │         │  └────────────────────┘  │
│  ├───────────────┤  │         │  私钥仅存签发环境        │
│  │ Anti-Rollback │  │         └──────────────────────────┘
│  └───────────────┘  │
└─────────────────────┘
```

**设计原则：**

- **离线可用**：合法期内不依赖联网；联网校验仅作后台增强。
- **本地可判定**：验签 + 机器码 + 有效期均在本地完成，不把「能否启动」绑在服务可达性上。
- **跨产品可复用**：算法、Token、存储、API 信封统一；仅 `app_name` 与 `APP_PREFIX` 按产品区分。
- **可演进**：Payload 含 `ver`；公钥可轮换；功能用 `edition` / `features` 扩展。

---

## 二、 硬件指纹与防跨机绑定设计

为防止软件被拷贝到其他主机运行，客户端必须生成唯一 **机器码（Machine Code）**，并与许可证严格绑定。

### 1. 算法版本

| 版本 | 标识 | 哈希 | 说明 |
| --- | --- | --- | --- |
| v2（**现行强制**） | `fingerprint_ver = 2` | **SHA-256** | WinPilot 已切换；**所有新项目必须使用** |
| v1（遗留） | `fingerprint_ver = 1` | MD5 | RCC / E-Player 历史授权可能仍在使用；现行客户端版本须逐一核验，禁止新项目使用 |

> **MD5 已废弃。** 机器码不是密钥，但统一到 SHA-256 可避免弱哈希与实现分叉。  
> WinPilot 从 MD5 迁到 SHA-256 后，旧授权中的 `machine_code` 全部失效，**必须按新机器码重签**。  
> RCC / E-Player 若有 v1 存量升级，同样需按实际迁移范围重签；当前发行包采用哪个版本须以各产品发布记录为准，不能仅根据历史快照推断。

### 2. 采集与归一化（必须按序尝试）

对每个硬件值执行归一化后再参与哈希：

1. `trim`，去掉首尾空白与 BOM（`﻿`）；
2. 转 **大写**；
3. 若落在无效值表中，视为「采集失败」：

| 无效值（比较时均为大写） |
| --- |
| （空）、`0`、`00000000`、`0000000000000000` |
| `DEFAULT STRING`、`NONE`、`NOT SPECIFIED`、`NOT AVAILABLE` |
| `SYSTEM SERIAL NUMBER`、`TO BE FILLED BY O.E.M.`、`TO BE FILLED BY OEM` |
| `UNKNOWN` |

**推荐采集顺序（任一路径成功即停止）：**

| 优先级 | 特征 A | 特征 B | 原始串 `raw` | 备注 |
| --- | --- | --- | --- | --- |
| 1 | `Win32_Processor.ProcessorId`（取第一颗） | `Win32_BaseBoard.SerialNumber` | `{A}-{B}` | 现网主路径 |
| 2 | `Win32_ComputerSystemProduct.UUID` | `Win32_BaseBoard.SerialNumber` | `{A}-{B}` | 部分 OEM 无 CPUID 时 |
| 3 | Windows 系统卷序列号 | （无） | `{8 位大写十六进制卷序列号}` | 直接作为机器码，不再哈希 |
| 4 | MAC（`uuid.getnode()` 的 48 位） | （无） | SHA-256 | 兜底，极弱，仅保底可用 |

**机器码（v2 / 现行）定义：**

```text
若优先级 1 或 2 成功:
    machine_code = SHA256( UTF-8( upper(raw) ) ).hexdigest().upper()   # 64 位大写十六进制

若优先级 3 成功:
    machine_code = f"{volume_serial:08X}"                               # 8 位大写十六进制

若优先级 4 成功:
    machine_code = SHA256( str(mac_int) ).hexdigest().upper()

若全部失败:
    不得使用「与产品无关的第三方 ID」凑数；
    应返回明确错误，并提示用户检查虚拟机/无序列号环境。
```

**实现约束（强制）：**

- **禁止使用已弃用的 `wmic`**。必须使用 CIM/PowerShell `Get-CimInstance`、`Win32` API 或等价受支持接口。  
  （E-Player 现网仍依赖 WMIC，属历史债，新项目不得模仿。）
- **禁止各端 fallback 到不同算法**。E-Player 在 WMIC 失败后退回 `node-machine-id`，导致与 RCC 注释「same as RCC」不符——规范明确禁止此类「静默换算法」。若必须降级，只能走上表优先级，并保证与本文一致。
- **禁止使用可移动存储设备的卷序列号**（U 盘、移动硬盘、SD 卡等）。路径 3 应查询 Windows 实际系统目录所在的固定卷；通常为 `C:\`，但不能假定所有机器的系统卷都叫 C:。
- 不要求「排除虚拟网卡」做模糊匹配；MAC 仅作最后一级兜底，且不得优先于路径 1–3。
- `uuid.getnode()` 的选卡行为不是跨语言协议。路径 4 当前只供人工审核/可选短试用，**不得声称跨产品得到同一码**；若将来正式开放该路径，需先规定网卡排序、虚拟/USB/随机 MAC 排除、无网卡时行为及跨语言测试向量。

### 3. 稳定性：外设变更与采集失败（强制）

目标：**插拔 U 盘、移动硬盘、打印机、扩展坞等，不得导致已授权机器码变化。**

| 路径 | 是否依赖可移动设备 | 说明 |
| --- | --- | --- |
| 1 CPU + 主板 | 否 | 稳定性最高，**签发首选** |
| 2 系统 UUID + 主板 | 否 | 稳定，签发可用 |
| 3 系统卷序列号 | 否（取 Windows 实际固定系统卷） | **禁止**枚举可移动盘 |
| 4 MAC 兜底 | 间接 | USB 网卡 / 随身 Wi‑Fi 理论上可能影响 `uuid.getnode()`，故 **禁止用于正式签发** |

**采集结果持久缓存（必须实现）：**

为避免「启动时 WMI/CIM 偶发失败 → 落到弱路径 → 机器码突变 → 已授权失效」，必须：

1. 首次通过路径 1 或 2 成功后，将 `machine_code` 写入 **DPAPI 保护** 的本地缓存（文件或注册表，与第四章同级防护）；
2. 每次启动：**优先现场采集路径 1/2**；成功且无缓存时写入缓存；与缓存不一致时保留缓存码、告警并走换绑，不得静默换码；
3. 若路径 1/2 **现场采集失败**，**回退使用已缓存的机器码**，**禁止**转而落到路径 3/4 导致码值突变；
4. **仅当从未成功缓存过**时，才允许路径 3/4 生成码，并标记 `fingerprint_path` 为弱路径。
5. **不得把路径 3/4 写入强路径机器码缓存**；弱路径仅供本次人工审核/短试用展示。旧版仅缓存 64 位字符串、无来源标记时，路径记为 `unknown`，不得据此自动领取试用；同码强指纹重新采集成功后才可升级缓存格式。

```text
启动获取 machine_code:
  live = try_path_1_or_2()
  if live 成功:
      若无缓存: 保存缓存(live) 并返回 live
      若有缓存且 live == 缓存: 返回 live
      若有缓存且 live != 缓存: 返回 缓存，并记录「硬件变更/异常」事件（不自动改绑）
  elif 有缓存:
      返回缓存          # 不得落到 path3/4
  else:
      return try_path_3_or_4()   # 弱路径，禁止用于正式签发
```

> 缓存经 DPAPI（CurrentUser）保护后，拷贝到其他机器无法解密，**不会**造成「把 A 机缓盘装到 B 机冒充 A」的简单攻击。

### 4. 唯一性与撞码（规范结论）

| 担心 | 结论 | 规范要求 |
| --- | --- | --- |
| SHA-256 碰撞 | 实际可忽略 | 继续使用 SHA-256，无需额外措施 |
| 两台机器码相同（同 raw 硬件身份） | **可能**，场景有限 | 见下 |
| U 盘导致码变化 | **主路径不会** | 强制缓存 + 禁用可移动卷 |

**可能「撞码」的场景（签发侧必须知道）：**

1. GHOST / 整机克隆、同批次无唯一序列号的 OEM 主板；
2. 虚拟机模板复制（同一 SMBIOS UUID / 同一虚拟主板序列号）；
3. 路径 3 仅 32 位卷序列号，机器数量大时冲突概率升高；
4. 路径 4 在无独立网卡、部分虚拟化环境下本身不唯一。

**签发策略（强制）：**

| 机器码来源 | 正式付费授权 | 试用 |
| --- | --- | --- |
| 路径 1 / 2（含有效缓存） | 允许 | 允许 |
| 路径 3 / 4 | **禁止自动签发**，需人工审核 | 可短时试用，并提示「机器指纹偏弱」 |
| 全部失败 | 不得签发 | 不得签发 |

服务端可对同一 `machine_code` 做绑定数限制（如同时仅 1 台）；克隆机场景应走换绑，而不是指望哈希唯一。

### 5. 跨机绑定策略（替代「80% 匹配」）

**不采用特征向量模糊匹配。** 原因：同型号 OEM、批量虚拟机、同配置上架机的硬件 ID 可高度相似，80% 容忍度接近一码多机。

绑定策略：

| 场景 | 处理 |
| --- | --- |
| 机器码精确相等 | 通过 |
| 机器码不相等 | **拒绝**，提示「授权不属于本机」 |
| 用户换主板/CPU 等导致机器码变化 | 走 **换绑/解绑** 流程（见第六章），由服务端作废旧绑定后重新签发 |
| 现场采集值 ≠ 缓存值（疑似硬件变更） | 以缓存继续使用当前授权，提示联系换绑；**不得**自动改绑 |
| 插拔 U 盘 / 扩展坞 / 非系统盘 | 机器码必须不变；若变了视为实现缺陷 |
| 供应商内部迁移 | 后台按 `license_id` 解绑，用户重新激活 |

---

## 三、 加密与安全机制

### 1. 签名算法（唯一：Ed25519）

| 项 | 规范 |
| --- | --- |
| 算法 | Ed25519（EdDSA） |
| 签名对象 | **payload 的原始字节**（UTF-8 JSON，不含首尾空白） |
| 公钥 | 客户端内置；只有经旧信任锚认证的新公钥或新版客户端预置公钥才能生效（见第九章） |
| 私钥 | 仅 license-service 签发环境；禁止入库、禁止进安装包 |

**不做 RSA-2048 备选。** 现网三端均为 Ed25519；规范二选一会导致新项目再次分叉。

### 2. 授权码（Token）字节级格式

```text
<APP_PREFIX> "." <base64url(payload_json)> "." <base64url(ed25519_signature)>
```

| 组成 | 规则 |
| --- | --- |
| 分隔 | 恰好 3 段，字符 `.` |
| `APP_PREFIX` | 见下表；**与 payload.app_name 双重校验** |
| base64url | RFC 4648 URL-safe 字母表；解码前若长度非 4 倍数则右侧补 `=`；编码端建议去掉 `=` |
| payload_json | 紧凑 UTF-8 JSON（建议 `sort_keys` 稳定序列化后再签名） |
| signature | Ed25519 对 `payload_json` 原始字节的 64 字节签名，base64url 编码 |

**产品前缀（现网兼容）：**

| 产品 | APP_PREFIX | payload.app_name |
| --- | --- | --- |
| RCC / ControlCommand | `RCC1` | `ControlCommand` |
| WinPilot | `WPL` | `WinPilot` |
| E-Player | `EPL` | `E-Player` |
| iCMS（仓库已注册前缀；公网启用需核对） | `ICMS` | `iCMS` |
| Rust Node（仓库已注册前缀；公网启用需核对） | `RUSTNODE` | `rust-node` |
| 新产品（须先注册） | `<PRODUCT_ABBR>` | 与签发记录一致 |

新产品建议使用短前缀（4–8 位大写字母/数字）；**同一产品线永不改前缀**，否则旧授权全部拒识。
前缀须在 license-service `TOKEN_PREFIXES` 注册，同时加入 `LICENSE_SERVICE_ALLOWED_APPS`；默认回退前缀 `RCC1` 不可用于新产品。注册后请在本表补一行（产品 / 前缀 / app_name），并在公网实际部署后核对公钥和签发结果。

### 3. Payload Schema（`ver = 1`）

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `ver` | int | 是 | Token 格式版本，当前 `1` |
| `app_name` | string | 是 | 必须等于客户端 `APP_NAME` |
| `machine_code` | string | 是 | 大写机器码，见第二章 |
| `expires_at` | string | 是 | **纯日期** `YYYY-MM-DD`（按客户端本地日历日比较） |
| `not_before` | string | 否 | 生效日 `YYYY-MM-DD`，默认立即生效 |
| `issued_at` | string | 否 | 签发时间 ISO8601 |
| `license_id` | string | 否 | 目标稳定 ID；本仓库当前签名载荷只有 `issue_id`，无 `license_id`，客户端不得凭空要求此字段 |
| `kid` | string | 否 | 签发公钥标识；新轮换 Token 必须填写，旧 Token 缺省映射到旧公钥 |
| `license_type` | string | 否 | `paid` / `trial` / `internal` 等 |
| `edition` | string | 否 | 如 `free` / `pro` / `enterprise`，驱动降级策略 |
| `features` | string[] | 否 | 功能开关列表，如 `["export","ocr"]` |
| `grace_days` | int | 否 | 宽限天数，缺省 `0` |

**示例 payload：**

```json
{
  "ver": 1,
  "app_name": "WinPilot",
  "machine_code": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "expires_at": "2027-12-31",
  "not_before": "2026-01-01",
  "issued_at": "2026-01-01T08:00:00Z",
  "license_id": "LIC-20260101-0001",
  "license_type": "paid",
  "edition": "pro",
  "features": ["export", "remote"],
  "grace_days": 7
}
```

示例机器码仅用于格式展示，不对应真实设备。本仓库 Token 签名载荷含 `issue_id`，不含 `license_id`；现网 `latest` 的 ID/载荷映射尚未核验，客户端不得仅凭响应中未经签名的 ID 更改本地授权身份。目标版须约定稳定 ID 与历史 `issue_id` 的映射，并以签名载荷中的稳定 ID 处理吊销与换绑。

**验签成功后的本地检查顺序（任一失败即拒绝）：**

1. 分段数 = 3，且 `APP_PREFIX` 匹配；
2. Ed25519 签名有效；
3. `ver` 受支持；
4. `app_name` == 客户端 `APP_NAME`；
5. `machine_code` == 本机机器码（大写比对）；
6. 解析 `expires_at` / `not_before` 成功（纯日期）；
7. 防回拨状态校验通过（见第五章）；
8. 若有 `not_before` 且今天 < 生效日 → 「授权尚未生效」；
9. 若今天 > `expires_at` + `grace_days` → 「授权已过期」；落在宽限内按第七章降级。

**日期语义（三端必须一致）：**

- `expires_at` / `not_before` 一律 **纯日期**，比较使用客户端本地日历的 `date`（时、分、秒归零）。
- 禁止使用带时区的 `new Date("YYYY-MM-DD")` 与 Python `datetime.date.today()` 混比（E-Player 历史问题）。各语言实现需统一为「本地日历日」。

### 4. 代码混淆与打包保护

在授权逻辑之外增加逆向成本（按语言选型）：

| 语言 | 建议 |
| --- | --- |
| C# / .NET | ConfuserEx / Dotfuscator；关键校验可 NativeAOT 或 ILProtector |
| C++ / C | VMProtect / Themida 对验签与机器码路径虚拟化；Strip symbols |
| Python | PyArmor + PyInstaller；禁用可轻易反编译的明文常量串拼接授权逻辑 |
| Node / Electron | asar 仍可解包；验签与机器码逻辑放入 native 模块或混淆后的二进制；私钥/公钥避免仅用纯 JS 常量存放于单一明文文件 |

> 混淆是提高成本，不是边界安全。授权安全主要依赖 Ed25519 私钥不出库。

---

## 四、 授权状态存储与防破坏恢复

目标：用户删配置文件、清注册表常规项后，仍能恢复授权或可审计地降级。

### 1. 存储策略（强制）

| 位置 | 内容 | 作用 |
| --- | --- | --- |
| 本地文件 | `%AppData%\<AppName>\license.dat` | 主存储 |
| 注册表 | `HKCU\Software\<AppName>\License` → `license_blob` | 冗余，防删文件 |
| 本地文件 | `%AppData%\<AppName>\license_state.dat` | 防回拨状态 |
| 注册表 | `HKCU\Software\<AppName>\License` → `state_blob` | 状态冗余 |

**加密原语（唯一推荐）：DPAPI**

- 调用 `CryptProtectData` / `ProtectedData.Protect`，Scope = **CurrentUser**，可选熵字符串 = 产品名。
- 写入磁盘/注册表的均为 DPAPI 保护后的 blob 的 **Base64 文本**。
- **禁止**使用「二进制里写死 AES 密钥」的自研加密。
- 文件与注册表记录应各自携带 `updated_at`（Unix 秒），并分别解密、校验完整性和授权签名；**在合法候选中**取较新者，不能因为时间较新就接受损坏/不匹配的记录。回写同步不得覆盖唯一合法备份。

**注册表细节：**

- 默认 **HKCU**（免管理员，随用户配置文件）。
- 仅当「安装模式、多用户共享授权」明确需要时使用 HKLM，并在文档中声明需管理员权限。
- 路径分隔使用语言原生写法（Python 中为 `r"Software\<AppName>\License"`），避免错误转义。

**可选（非必须）：** ADS、额外隐藏文件。因网盘同步/备份工具常丢失 ADS，**不得**将 ADS 作为唯一辅助通道，也不得因 ADS 写失败而拒绝授权。

### 2. 启动恢复与同步逻辑

```text
启动:
  1. 分别读取 file_license, reg_license，解密 DPAPI
  2. 分别执行第三章验签 + 机器码检查，剔除损坏/吊销的候选
  3. 在合法候选中取 updated_at 较新者
  4. 成功:
       - 回写 file + reg（刷新 updated_at）
       - 读/验防回拨状态，通过则保存本次时间戳
  5. 失败但另一处有合法备份:
       - 用备份恢复并提示「授权已恢复」
  6. 两处均无:
       - 若存在设备恢复凭据（可选，见下）→ 联网静默重拉
       - 否则进入未授权状态（按产品策略：拦截 API / 试用 / 只读）
```

**静默云端恢复（可选增强）：**

- 若实现「设备 Token 静默重拉」，Token 的保护等级必须与授权码相同（DPAPI + 双写），且服务端限制重拉次数与频率。
- **禁止**「仅凭机器码、不持有任何本地凭据即可无限拉回许可证」——那等价于把授权码公开。
- 本仓库已实现设备公钥登记与挑战签名后的 `POST /api/v1/licenses/latest`（§8.1），但在该版本实际部署并更新客户端之前，现网原有 `GET /licenses/latest` 仍是上述禁止情形的**过渡缺口**。客户端私钥以 DPAPI 保护，离线/已有付费设备由管理员核验登记；机器码本身不是秘密，不得当作认证凭据。首次试用的自助登记仍存在“知道机器码的人抢先占用”风险，不能将软件公钥签名冒充硬件身份证明。
- 文件、注册表与本地状态全部被删除时，DPAPI/HMAC 本身不能证明过去运行过；不得据此重置试用。重装恢复只能走服务端的一机一次记录、有效设备凭据或人工签发。

### 3. 导入导出注意

- 导出配置/整库备份若包含授权字段，导入后应视为「授权可迁移」，但机器码仍校验；跨机导入必然失败，属预期行为。
- UI 文案应提示：换机需重新激活或申请解绑。

---

## 五、 防时间回拨

必须防止「改系统时间续期」。采用 **签名状态 + 可信时间源** 双层。

### 1. 本地签名状态

每次验签成功后保存：

```json
{
  "last_run_ts": 1760000000,
  "license_id": "LIC-...",
  "expires_at": "2027-12-31"
}
```

- 对 `last_run_ts`（及如需的整段状态）计算 **HMAC-SHA256**，或整段 DPAPI 保护后再双写。
- **禁止**将 HMAC 密钥以可猜测默认值硬编码进发行版（RCC 现网默认 `RCC1StateKey2026!` 属历史债）。密钥来源优先级：
  1. 构建期注入的独立密钥 / 环境变量（仅开发调试）；
  2. 首次运行生成随机密钥并写入 DPAPI 保护的密钥槽；
  3. 不得使用全局公开常量。

### 2. 可信时间源（联网时）

校验当前时间前，可尝试获取经 TLS 校验的 HTTPS `Date` 头（建议多个独立源，超时 2–3 秒）：

- `https://www.microsoft.com`
- `https://www.baidu.com`
- 或 license-service 响应中的 `server_time`

若取到网络时间，则用网络时间作为 `now`；否则退回本地时钟。容差 **300 秒**（可配置，默认 300）。
必须明确来源优先级、不可达时的退化策略与启动时限；不能把可被中间人替换的明文 HTTP 时间或任意 JSON 字段当可信时间。无网、全删本地状态和管理员手动改时钟无法由客户端单独完美判定，应记录风险并用服务端签发/防重复试用兜底。

### 3. 状态机（必须实现）

设 `now` 为可信时间，`last_run_ts` 为上次成功运行时间，`expire_date` 为授权到期日：

| 条件 | 结果 |
| --- | --- |
| 状态签名/DPAPI 校验失败 | 拒绝：「授权状态被篡改」 |
| `now + 容差 < last_run_ts` | 拒绝：「系统时间异常，禁止回退」 |
| 历史 `last_run` 落在 `expire_date` 之后仍记录过运行 | 拒绝：「授权已过期（检测到历史过期记录）」 |
| 今天 > `expire_date` + `grace_days` | 拒绝或降级（见第七章） |
| 以上均通过 | 允许，并更新 `last_run_ts = max(now, last_run_ts)` |

试用期额外规则：检测到时间大幅回退时 **直接锁定试用**，不进入宽限。

---

## 六、 激活模式与试用期设计

### 1. 在线激活（Online）

1. 用户输入激活码 / 授权码，**或点击「申请试用」自动领取**（见 6.3，默认传 `trial_days: 30`）。
2. 客户端采集 `machine_code`，按第八章调用 license-service。
3. 服务端核销、绑定机器码（或签发试用 Token），返回 **License Token**（`PREFIX.b64.sig`）。
4. 客户端本地验签通过后写入 DPAPI 双写存储。

### 2. 离线激活（Offline / Air-gapped）

1. 客户端展示/导出机器码（或 `machine_info.json`：`app_name` + `machine_code` + `fingerprint_ver`）。
2. 用户在有网设备的管理后台上传机器码并绑定激活码。
3. 下载离线授权文件（内容即 License Token 字符串，扩展名 `.lic` 可选）。
4. 导入客户端 → 本地验签 → 入库。

**要求：** 离线许可与在线许可 **使用同一 Token 格式与验签代码**，仅获取途径不同。

### 3. 试用（Trial）——统一模型

| 层级 | 设计 | 说明 |
| --- | --- | --- |
| **首选：服务端签发试用 Token** | `POST /api/v1/trial/apply`，`license_type=trial` | 防「清配置重置试用」；机器码级去重 |
| 可选：本地短试用 | 默认关闭；如业务必须启用，明确可重装重置的风险、最长时长和人工审核补救 | DPAPI 双写不能替代服务端的一机一次记录 |
| 禁止 | 仅用「明文注册表时间戳」做试用 | 清注册表即可重置 |

#### 3.1 申请试用的标准方法（含 1 年试用）

> **给实现者 / AI 编码代理：**  
> 产品需要开放试用（默认 **30 天**）时，按本节实现「一键申请试用」。  
> **不要**让用户手工找供应商要码；联网即可自动领取并自动激活。

**A. 客户端 UI（必须有）**

1. 未授权时进入激活页，展示 **机器码**（可一键复制）。
2. 若 `license_service_url` 已配置，显示主按钮：**「申请试用」/「领取试用」**（产品开放 1 年时文案可为「申请 1 年试用」）。
3. 客户端先生成并用 DPAPI 保护 Ed25519 设备私钥，再按 §8.1 获取 `trial` 挑战并签名，调用 `request_trial()`；成功后刷新授权状态，**无需用户粘贴 Token**。
4. 失败展示错误并允许重试（客户端冷却 ≥ 60s）。

**B. 申请试用（N 天，含 1 年 / 90 天等）——请求方法**

```http
POST {license_service_url}/api/v1/trial/apply
Content-Type: application/json
User-Agent: {AppName}-License-Client/{version}
```

```json
{
  "app_name": "YourAppName",
  "machine_code": "本机机器码（大写，附录 A）",
  "app_version": "1.2.3",
  "fingerprint_ver": 2,
  "trial_days": 90,
  "device_public_key": "原始公钥的无填充base64url",
  "challenge": "服务端trial挑战",
  "signature": "设备私钥对规范化挑战消息的无填充base64url签名"
}
```

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `app_name` | 是 | 与签发配置一致 |
| `machine_code` | 是 | 附录 A 算法输出 |
| `app_version` | 建议 | 客户端版本 |
| `fingerprint_ver` | 建议 | 当前为 `2`；本仓库服务端暂不核验该字段或弱路径来源 |
| **`trial_days`** | **建议显式发送** | 如 `30` / `90` / `365`。**默认 `30`**。服务端按产品策略钳制上限 |
| `device_public_key` | 是 | 32 字节原始 Ed25519 公钥的无填充 base64url；首次试用绑定，重复试用必须与已绑定公钥一致 |
| `challenge` / `signature` | 是 | 先获取 `action=trial` 的一次性挑战；按 §8.1 规范化消息签名，旧无签名请求不再兼容 |

> **通用规则：** 任何试用时长都只改 `trial_days`，客户端代码共用同一套「申请试用」流程。  
> 例如：默认开放 → `trial_days: 30`；开放 90 天 → `trial_days: 90`；特殊审批 1 年 → `trial_days: 365`。

**成功响应（假设首次签发日为 2026-10-17，且产品上限不低于 90 天）：**

```json
{
  "ok": true,
  "data": {
    "license_key": "XXX.yyy.zzz",
    "license_type": "trial",
    "expires_at": "2027-01-15",
    "trial_days": 90
  }
}
```

**C. 客户端处理返回（必须按序）**

1. 本地 `verify_signed_license(license_key)`（签名、`app_name`、机器码、有效期）。
2. 失败：不落盘，原样报错。
3. 成功：`install_license(license_key)` 写入 DPAPI（第四章）。
4. 刷新 UI（到期日、`license_type=trial`）。

**D. 产品「开放 1 年试用」实现清单**

- [ ] 客户端常量/配置：`TRIAL_DAYS = 30`，请求体带 `trial_days: 30`。
- [ ] 按钮文案：`申请 1 年试用`。
- [ ] 服务端/管理台允许该 `app_name` 签发 **30** 天 trial（上限由 `LICENSE_SERVICE_TRIAL_DAYS` 控制）。
- [ ] 同 `machine_code` **只获得一个首次到期日**；本仓库重复申请返回新签 Token 但不延长期限，过期返回 409 `trial expired`。
- [ ] 到期策略按第七章。

**E. 默认时长（未传 `trial_days` 时）**

| 场景 | 默认 |
| --- | --- |
| 请求含 `trial_days`（如 `90` / `365`） | 以请求为准，**服务端钳制到产品上限** |
| 产品要求 1 年试用 | 客户端传 `365`（或服务端对该产品默认 365） |
| 一般商用 | **30** 天 |
| 演示/调试 | 10 分钟本地试用（须倒计时） |

**F. 产品配置示例**

| 需求 | 客户端 `TRIAL_DAYS` | 请求 |
| --- | --- | --- |
| 开放 1 年试用 | `365` | `"trial_days": 365` |
| 开放 90 天试用 | `90` | `"trial_days": 90` |
| 开放 30 天试用 | `30` | `"trial_days": 30` |

#### 3.2 其他试用规则

- 试用 Token 与付费 Token **同一验签代码**，仅 `license_type` / 有效期不同。
- 客户端仅对 `fingerprint_path ∈ {1,2}` 自动领试用；路径 3/4 人工审核或短试用并提示弱指纹。本仓库服务端不校验指纹强弱，不得声称服务端阻断弱路径或同码克隆。
- 无网：提供离线申请入口；未启用本地短试用时保持未授权界面，不得闪退，也不得假称已获得试用。
- 时间回拨直接锁定试用（见第五章）。

试用到期行为见第七章（默认强提醒 + 降级或退出，由产品选择一种并写入产品页）。

### 4. 解绑 / 换绑

| 操作 | 规则 |
| --- | --- |
| 用户自助解绑 | 后台按 `license_id` 释放绑定次数；限制 N 次/年（如 3） |
| 供应商强制解绑 | 审计日志必留 |
| 解绑后旧 Token | 服务端标记 `revoked` 后 `latest` 不再返回——**在线设备经 supersede/latest 同步已闭环**（见 §续签·降期）；已下发的离线 Token 本地验签在有效期内仍成立（离线验签固有边界） |
| 未联网 | 本地仍按 `expires_at` 有效，直至下次联网同步 |

---

## 七、 过期策略与灵活性处理

过期后行为由 `edition` + `grace_days` + 产品配置共同决定。**同一产品线只选一种默认策略**，写进产品说明。

| 策略 | 行为 | 适用 |
| --- | --- | --- |
| **降级使用** | 到期后不锁死，关闭高级功能（读 `features` / `edition`） | 工具型、需保留基础能力 |
| **宽限期** | 到期后 `grace_days` 天内正常用，每次启动提醒续费 | 订阅型、B 端 |
| **硬停** | 到期即拒绝业务功能，仅保留激活/设置/日志 | 严格授权 |

**离线缓存宽限：** 本地 Token 的 `expires_at` 未到（或仍在 `grace_days` 内）时，**不得**因服务不可达而拒绝启动。联网后后台同步；若服务端返回 `revoked`/`expired`，在下次启动或宽限策略允许时收紧。

**运行中到期：**  
- 软降级：立即生效；  
- 硬停：允许保存当前工作，限制新操作；  
- 不建议静默闪退。

### 7.1 过期/到期续签流程（标准）

当前已部署客户端可用的是管理员新签 Token 后**手动交付、客户端本地验签导入**。本仓库实现了认证领取服务端，但自动拾取必须等**客户端保存设备私钥并完成实际部署与联调**后才能启用：

**路径 A — 在线自动拾取续期（本仓库服务端实现；需客户端升级）**

```text
管理员侧：
  登录 /admin → 「续期」→ 填 app_name + machine_code（客户授权信息页可复制）
  → 设新到期（如 +10 年）→ 提交（POST /api/v1/licenses/renew）
  → 服务端签发新 license_key（新到期、新 issue_id），旧记录保留可追溯

客户端侧（升级后流程）：
  ① 首次试用自助登记设备公钥（旧设备由管理员人工登记），客户端以 DPAPI 保存私钥；
     周期复查（默认每 6h，可配）或点击「立即检查续期」
     → 取得 action=latest 的短时一次性挑战并用设备私钥签名
     → POST /api/v1/licenses/latest 提交产品、机器码、挑战与签名
     → 服务端校验产品、设备公钥、挑战和登记/吊销状态，仅返回未过期在线授权
  ② 本地 Ed25519 验签（只使用构建期内置或由旧可信公钥认证的新公钥；
     验不过不得直接下载另一把公钥重试）
  ③ 验签通过且为新授权 → 按第四章 DPAPI 双写存储 → 有效期自动延长
  ④ 授权失效时：warn 模式仅提示；block 模式业务 API 返回 503，
     页面显示「软件未授权」+「重新检查授权」按钮，续签后一键恢复
```

要点：
- 本仓库的设备认证拾取和管理员登记/吊销**仅约束联网取回**：在线设备的吊销/降期经 `renew`+`supersede` → `latest` 复查已闭环（见下）；**已签离线 Token 不会因吊销而自动失效**（本地验签固有特性）。旧现网 `GET latest` 仍不得当作安全恢复接口。
- **缩短有效期（降期）的标准操作**：`renew` + `"supersede": true`（管理页续期弹窗
  即「签发前吊销该设备旧授权」勾选项）。服务端先吊销该设备全部旧 active 授权
  （`latest` 只返回未吊销且未过期记录），再签发新的短期限授权——**缩短时必须勾选**，
  否则旧长期限记录仍在，客户端复查按最长未吊销记录返回，新短期限不会生效。
- 客户端联网复查（`latest` 拾取）验签通过后**采用服务端最新签发，即使到期日早于
  本地缓存**（2026-10-19 起）。服务端签名响应是可信根，更短的签发就是管理员
  吊销重发的合法意志；客户端本地防回拨/防篡改由本地 HMAC 状态行与时钟回退检查
  负责，不以“到期日更短”为由拦截（攻击者持签名私钥可直接签长期，发更短无收益，
  该比较拦不住真威胁却阻塞合法降期）。离线导入同理：验签通过即采用。
- 网络超时、TLS 错误、路由 404 等不得误判为吊销；客户端应保持本地尚未过期的可信 Token。

**路径 B — 手动交付续签（当前可用；在线或离线客户端均可）**

```text
管理员侧：
  /admin → 「离线签发」（POST /api/v1/licenses/offline-issue）
  → 填 app_name + machine_code + 新到期 → 得到 license_key（完整 Token）

客户侧（手动一步）：
  将 license_key 以文本/文件形式交付（U盘、IM、邮件）
  → 客户端「手动输入授权码/导入授权文件」→ 本地 Ed25519 验签
  → 验签通过 → 按第四章 DPAPI 双写 → 到期延长
  验签失败（错机器码/篡改/过期签发）→ 提示对应错误码（见附录 E），不得落盘。
```

> 试用与续签边界：每机器码试用仅可领取一次；试用到期后 `trial/apply` 返回 409
> `trial expired`，现阶段延期走路径 B；路径 A 仅在认证续签接口完成后启用。

---

## 八、 对接 `c3812600/license-service` 接口规范

### 0. 通用约定

| 项 | 约定 |
| --- | --- |
| Base URL | `https://licenses.lonk.vip`（现网已生效，经 Cloudflare 隧道回源；客户端 `LICENSE_SERVER` 配置项） |
| Content-Type | `application/json` |
| 成功信封 | `{"ok": true, "data": {...}}` |
| 失败信封 | 当前实现为 `{"ok": false, "error": "..."}`；目标版才增加稳定业务 `code` |
| 超时 | 建议 10s；试用/激活可 15s |
| TLS | 必须校验证书；Python 可用 certifi / 自定义 CA |
| User-Agent | `{AppName}-License-Client/{version}` |
| 客户端原则 | **启动不依赖接口**；仅激活、试用、后台校验、吊销同步时调用 |

### 1. 三层接口清单（先核对部署版本，再对接）

| 范围 | 动作与路径 | 鉴权/请求 | 响应与限制 |
| --- | --- | --- | --- |
| 本仓库 | `GET /api/v1/health`、`GET /api/v1/public-key` | 无 | 健康信息、公钥 PEM；公钥仅供构建期独立核对 |
| 本仓库（**已部署**，2026-10-18 起强制） | `POST /api/v1/devices/challenge` | `app_name`、`machine_code`、`action=trial/latest/register` | 一次性 `challenge`：trial/latest 120 秒，人工 register 900 秒；公开领取，需代理限流 |
| 本仓库（**已部署**） | `POST /api/v1/trial/apply` | `app_name`、`machine_code`、`device_public_key`、`challenge`、`signature`；可选 `trial_days` | 首次绑定设备公钥并签发试用；重复领取须原私钥；忽略可选 `fingerprint_ver` |
| 本仓库（**已部署**） | `POST /api/v1/licenses/latest` | 已登记设备对 `latest` 挑战签名 | 仅未过期、active 的在线 Token；不返回 `offline_manual`；无有效授权 404，不等于吊销 |
| 本仓库（**已部署**） | `POST /api/v1/devices/register`、`POST /api/v1/devices/revoke` | 管理员 Token；登记时还需新私钥对 `register` 挑战的签名 | 管理员人工登记/轮换/停用设备公钥；停用不撤销已有签名授权 |
| 本仓库 | `POST /api/v1/licenses/renew`、`POST /api/v1/licenses/offline-issue` | `X-Admin-Token` + `app_name`、`machine_code`、`expires_at` 等 | 新签 Token；默认不撤销已有 Token，**缩短到期必须带 `"supersede": true`**（见 §续签·降期）；不得从客户端携带管理员 Token |
| 本仓库 | `GET /api/v1/licenses/query`、`GET /api/v1/stats` | `X-Admin-Token` | 仅管理员查询或统计；`/admin`、`/admin/stats` 为管理页面 |
| **已移除** | `GET /api/v1/licenses/latest` | 现返回 **405** | 旧接口已删除，不能安全认证设备；旧客户端必须升级到设备签名版 |
| 现网观察 | `GET /api/v1/stats`、`GET /admin/stats` | 未授权时 stats API 返回 401 | 路由可达；未验证管理员实际数据 |
| 目标未上线（**可选，不阻塞闭环**） | `/api/v1/activate`、`/api/v1/validate` | 接口待定稿 | 在线收紧心跳已由 `latest` + 客户端周期复查覆盖（默认 6 小时，间隔可配）——吊销/降期经 `renew+supersede` 后下次复查即生效；`validate` 仅对非本协议的第三方客户端有价值 |

客户端在拿到 `license_key` 后，**必须本地验签通过才落盘**，不得信任服务端仅返回成功。
`latest` 的机器码可被获知/仿造，不是身份认证；旧 GET 接口不得继续使用。认证新版的 HTTP 404 仅表示此次查询无可领取的 active 在线授权，路由不存在、网络故障、设备凭据停用或离线授权不能据此判定为许可证吊销。**在线设备的吊销/降期同步已闭环**（`renew`+`supersede` 吊旧签新，`latest` 复查生效，见 §续签）；已下发的离线 Token 收不回（离线验签固有边界）；稳定业务码仍是目标。

**设备签名契约（本仓库实现，需客户端升级；与发行方 Token 的 Ed25519 密钥对完全独立）：**

1. 客户端每个产品/机器生成 Ed25519 设备密钥对，私钥仅留本机并用 DPAPI 保护；首次试用自助登记，已有试用/付费记录未登记者必须管理员人工核验并登记。首次自助登记无法证明真实硬件身份，存在已知机器码被抢先占用的残余风险。
2. 客户端 `POST /api/v1/devices/challenge` 发送 JSON `{"app_name":"ControlCommand","machine_code":"本机机器码","action":"trial"}`（续期取回用 `latest`，管理员登记用 `register`）。返回 `data.challenge`（43 位无填充 base64url）和 `expires_in`；试用/领取 120 秒，人工登记 900 秒。机器码去空格转大写后限 8-128 位字母/数字/冒号/下划线/连字符，**自助试用还要求 64 位十六进制 SHA-256 码**。
3. 对以下**无尾部换行**的 UTF-8 字节签名，每行以单个 LF (`\n`) 分隔；`device_public_key` 是 32 字节原始公钥的无填充 base64url（43 位），`signature` 是 64 字节签名的无填充 base64url（86 位）。挑战绑定动作、产品、机器，只能成功使用一次：

```text
license-service/device/v1
{action}
{app_name}
{normalized_machine_code}
{challenge}
```

**跨语言签名对拍向量（固定测试密钥，绝不可用于生产）：** Ed25519 私钥原始 32 字节 seed 为 `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`；`action=latest`、`app_name=ControlCommand`、`machine_code` 为 64 个大写 `A`、`challenge` 为 43 个大写 `A`。按上述规则拼接的签名输入共 156 字节（UTF-8、LF、无尾换行）。无填充 base64url 公钥为 `A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg`，签名为 `HNhvGmg8ez2IrCEP2uypAGDkMHOmGsribExv25ujZSZ5zRIxKdfLucahMQRhufmCdjcWFRJxd1Ljvu2KKUIeAw`。此固定挑战仅用于本地对拍，不能向线上提交。

4. 首次 `trial/apply` 除常规字段外提交 `device_public_key`、`challenge`、`signature`；再次申请使用原公钥和新 `trial` 签名。`POST /api/v1/licenses/latest` 使用新 `latest` 挑战，仅提交 `app_name`、`machine_code`、`challenge`、`signature`；不得在 GET URL 传机器码或管理员 Token。管理员 `devices/register` 接收新密钥的 `register` 挑战/签名和 `X-Admin-Token`，可登记或轮换；`devices/revoke` 接收产品/机器码与管理员 Token，仅停用联网取回能力。丢私钥必须走管理员人工审核，不能凭机器码重领；旧 GET 和无签名试用协议不兼容。
5. 设备私钥用于**取回授权码**，不能代替客户端对返回 Token 做独立的发行方 Ed25519 验签、机器码、产品和日期核对。可用的硬件保护优先，但不假设所有 Windows 版本都支持不可导出的 Ed25519。服务端不返回已过期、已标记撤销或 `offline_manual` 记录；设备公钥停用**不会**让已落盘签名 Token 自动失效。

**本仓库试用规则**：建议客户端显式发送 `trial_days`（§6.3.1）；产品上限由 `LICENSE_SERVICE_TRIAL_DAYS_MAP`（JSON：`{"<app_name>": 天数}`）指定，未配置用全局 `LICENSE_SERVICE_TRIAL_DAYS`（代码默认 365，仓库示例配置为 30）。未传/非法时取产品上限，有效正整数钳制到上限。新签试用以服务端 **UTC 日期**计算首次到期日；响应 `data.trial_days` 是首次实际发放天数。并发请求在数据库事务中串行处理，重复领取新签 Token 但沿用**首次到期日**，已过期后申请返回 409 `trial expired`。代码及示例配置默认允许 `ControlCommand`、`E-Player`、`WinPilot`、`iCMS`、`rust-node`，生产可通过 `LICENSE_SERVICE_ALLOWED_APPS` 收窄。此规则是代码与测试结论，公网还须用安全测试环境单独联调。

### 2. 尚未实现的目标标准接口

| 动作 | 方法与路径 | 请求 | 响应 `data` | 说明 |
| --- | --- | --- | --- | --- |
| 激活 | `POST /api/v1/activate` | `{"key","app_name","machine_code","app_version","fingerprint_ver"}` | `license_token`、`license_id`、`expires_at` | 核销激活码并绑定 |
| 设备换绑/完整凭据恢复 | 接口待定 | 原设备证明或人工审批与新密钥 | 新设备登记状态 | 当前仅支持管理员登记/轮换公钥，尚无自助换绑或账户级凭据恢复 |
| 校验/心跳 | `POST /api/v1/validate` | `license_token` 或 `license_id` + `machine_code`；设备凭据/管理凭据认证 | `status`: `active`/`expired`/`revoked`/`grace`，`server_time` | 可静默周期调用；不能把机器码当认证 |
| 离线申请 | `POST /api/v1/offline-license` | `{"key","app_name","machine_code","fingerprint_ver"}` | `license_token`（同格式） | 供管理台代发 |
| 解绑 | `POST /api/v1/unbind` | `{"license_id","machine_code"}` + 管理员/经授权的设备凭据 | `ok` | 校验解绑权限、次数、审计；仅 ID/机器码不能解绑 |
| 吊销查询 | `POST /api/v1/revoked` | `{"license_id"}` + 经授权的凭据 | `revoked`: bool | 可并入 validate，防止枚举与状态泄露 |

**与现网映射：**

| 目标接口 | 现网替代 |
| --- | --- |
| activate | 暂无统一接口；试用走 `trial/apply`，正式授权目前签发后手工/脚本交付 Token |
| validate | 无；客户端以本地验签为准，可调用 `public-key` 做连通性探测 |
| offline-license | 无；管理台人工签发 |

> 上表为**目标设计，不代表现网已实现**。设备公钥登记与挑战式取回已在本仓库实现但尚未部署或完成真实 Windows 客户端联调；凭据丢失后只能管理员人工登记。`issue_id` 与目标 `license_id` 尚无稳定映射，不能将联网取回能力误写为完整吊销/换绑能力。

### 3. 网络容错

- 网络超时、TLS 错误、5xx、429：**不得**使本地未到期且未确认吊销的授权失效；本地过期和已经确认的吊销不受此条保护。
- 续期拾取建议默认每 6h（产品可配）；独立吊销心跳在目标 `validate` 上线后可每 3–7 天或按产品风险设置。两者不是同一个频率，失败应指数退避。
- 收到 `revoked`：按第七章产品策略收紧；写本地标记，避免每次启动都打服务端。
- 限流与防爆破：客户端对激活/试用失败做冷却（如 60s）；服务端按 IP/机器码限流。

### 4. 错误码（客户端可识别）

| code | 含义 | 客户端 UX |
| --- | --- | --- |
| `MACHINE_MISMATCH` | 机器码不匹配 | 展示本机机器码，引导换绑 |
| `EXPIRED` | 已过期 | 提示续费/降级 |
| `NOT_BEFORE` | 未生效 | 提示生效日 |
| `SIGNATURE_INVALID` | 签名无效 | 提示重新获取授权 |
| `REVOKED` | 已吊销 | 强提示联系供应商 |
| `TIME_ROLLBACK` | 时间回拨/状态异常 | 提示校准时间 |
| `ACTIVATION_LIMIT` | 绑定次数超限 | 引导解绑或联系供应商 |
| `SERVICE_UNAVAILABLE` | 服务不可用 | 静默重试，不影响本地有效授权 |
| `LICENSE_REQUIRED` | 业务 API 未授权 | 进入激活/申请试用页 |

---

## 九、 公钥管理与轮换

1. **内置公钥**：构建时经独立渠道核对原始 Ed25519 公钥的 SHA-256 指纹，再嵌入发行版；安装目录中的 PEM 文件或运行时环境变量不得无条件覆盖正式版信任锚。
2. **运行时更新条件**：`GET /api/v1/public-key` 的 HTTPS 仅保证传输连接，**不能单独授权更换信任锚**。目标版先用当前可信私钥签署包含 `kid`、新公钥、有效期及产品标识的轮换清单，由旧内置公钥验证；或者发新版客户端预置双公钥。清单格式/接口尚未实现，不得在验签失败时直接信任刚下载的公钥。
3. **轮换流程（目标）**：
   - `kid` 固定放入新 Token 的**签名 payload**（当前三段格式没有独立头段）；旧 Token 缺省采用旧公钥；
   - 客户端先支持旧/新双公钥验签，再切换服务端签发私钥；
   - 旧 Token 若仍在有效期内必须可验，除非先重签并送达用户；180 天仅为建议窗口，不得短于旧 Token 剩余有效期；
   - 轮换结束后发布记录旧公钥退役时间、影响范围和回滚步骤。
4. **私钥**：仅签发机/密钥管理系统；禁止提交 Git；备份加密；操作留审计。

---

## 十、 客户端标准模块划分

新项目直接使用下列模块边界，避免第五次各写各的：

```text
license/
  machine_id.py      # 第二章：采集、归一化、machine_code
  token.py           # 解析 PREFIX/payload/sig，base64url
  verify.py          # Ed25519 验签 + payload 校验
  storage.py         # DPAPI 双写 file+reg，updated_at 冲突解决
  anti_rollback.py   # 第五章状态机
  trial.py           # 服务端试用申请；本地短试用默认禁用
  service.py         # HTTP 客户端：public-key / trial / activate / validate
  errors.py          # 错误码与文案
```

**对外最小接口建议：**

```text
get_machine_code() -> str
verify_license(license_text) -> (ok, msg, payload)
install_license(license_text) -> (ok, msg)
get_license_status() -> {installed, valid, message, machine_code, license_id, expires_at, edition, features}
request_trial() -> (ok, msg, payload)
ensure_license(silent=False) -> bool   # 启动入口
```

**服务端辅助 API（各产品自定）：**  
系统级路径（登录、授权、健康检查）应明确列出最小豁免名单；设置/日志是否豁免需逐项评估写操作，不能仅按 `/api/` 前缀判断。业务 API 与 WebSocket/本地 IPC 均须复核登录、来源和授权。通用推荐未授权返回 `LICENSE_REQUIRED`（HTTP 403）；若产品已有不同兼容契约（如 Rust Node 返回 503），必须在产品附录声明，不得让客户端依赖一个未实现的状态码。

---

## 十一、 日志与合规

- 客户端日志可记录 `license_id`、校验结果、错误码；**禁止完整授权码**写入日志/崩溃转储。
- 服务端审计：签发、试用、激活、解绑、吊销、公钥下载；保留 IP、机器码哈希（或可逆场景下的明文策略需法务确认）。
- 隐私：向用户展示的机器码可原样（便于售后）；上传仅 `machine_code` 必要字段，不采集用户名文档等无关隐私。
- UI 文案语言与产品一致（E-Player 历史英文报错应改为中文或可本地化资源）。

---

## 十二、 测试矩阵（发布前必过）

| # | 用例 | 期望 |
| --- | --- | --- |
| 1 | 首次安装无授权 | 进入激活/试用，不闪退 |
| 2 | 导入合法 Token | 激活成功，状态展示到期日 |
| 3 | 篡改 payload 后导入 | 签名失败 |
| 4 | 换机器码（改虚拟机 UUID / 另一台） | 拒绝，提示机器码不匹配 |
| 5 | 删除 `license.dat`，保留注册表 | 自动恢复 |
| 6 | 清注册表，保留文件 | 自动恢复 |
| 7 | 文件与注册表均删除 | 未授权/试用，或静默重拉（若实现） |
| 8 | 系统时间改到未来后再改回 | 禁止回退或状态异常 |
| 9 | 系统时间改到过去 | 拒绝运行或锁定试用 |
| 10 | 断网启动 | 本地有效授权可正常使用 |
| 11 | license-service 宕机 | 同 10 |
| 12 | 到期日当天 00:00–23:59 | 按 `expires_at` 纯日期语义，当天仍有效（或按产品定义，但需测） |
| 13 | 宽限期启动 | 提醒 + 策略符合第七章 |
| 14 | 试用到期 | 按产品策略降级/退出，可再次引导激活 |
| 15 | 重复领取试用 | 本仓库新签 Token 但沿用首次到期日，过期返回 409；并发不叠加时长 |
| 15b | **一键申请试用（1 年 / trial_days=365）** | 自动签发 + 本地验签 + 入库，用户无需粘贴 |
| 16 | 吊销后联网 validate（目标接口上线后） | 收紧策略生效；本仓库无接口 |
| 17 | 公钥轮换后旧 Token（目标能力上线后） | 旧 Token 有效期内仍可验 |
| 18 | 多用户切换（HKCU） | 各用户授权隔离或按产品定义 |
| 19 | VM / 无序列号机器 | 走降级路径或明确提示，不产生不稳定机器码 |
| 20 | 中文路径 / 无管理员权限 | 存储与激活正常 |
| 21 | **插入/拔出 U 盘、移动硬盘** | 机器码与授权状态**完全不变** |
| 22 | 插入 USB 网卡（已缓存主路径） | 机器码不变 |
| 23 | **临时禁用 WMI/CIM 或采集超时** | 仍返回缓存机器码，授权不失效 |
| 24 | 删除机器码缓存但硬件可采集 | 重算得同一码，授权仍有效 |
| 25 | 将他机 DPAPI 缓存文件拷到本机 | 无法解密或不被采信，不得冒充他机 |
| 26 | 同码克隆机（模拟相同 raw） | 在线签发侧限制与审计；离线同码克隆无法仅靠客户端可靠区分，须明确残余风险 |
| 27 | 两处授权存储一处损坏且更新时间较新 | 仍选另一处**验签合法**的备份，不被坏记录覆盖 |
| 28 | 目标认证续期接口的路由 404、无 active 业务码、网络超时各一次 | 区分业务码与传输错误；仅认证且确认吊销后持久化标记 |
| 29 | 无设备凭据、持伪造机器码请求目标续期接口 | 拒绝返回完整 Token；限流并审计 |
| 30 | 服务端换签发密钥、新旧 Token 并存 | 仅已认证的新公钥生效；旧有效 Token 可验；未知 `kid` 拒绝 |
| 31 | 全删用户数据再安装、重复领试用 | 服务器维持一机一次；离线无有效凭据不得自动重新发放 |
| 32 | 安装/升级、无管理员权限、卸载重装 | 程序目录只读可运行；授权/工作流在用户数据目录且不被升级覆盖 |
| 33 | 未登录直连 WebSocket、跨站请求、授权到期期间持续连接 | 握手及连接存续均受门禁控制，不得执行注入等业务操作 |

---

## 十三、 落地实施清单（Checklist）

- [ ] **Step 1** 按附录 A 实现机器码模块：路径 1/2 + DPAPI 缓存回退 + 弱路径标记，并用附录 A 逻辑对拍。
- [ ] **Step 2** 实现 Token 解析与 Ed25519 验签（附录 B），内置公钥。
- [ ] **Step 3** 实现 DPAPI 双写存储与恢复（第四章）。
- [ ] **Step 4** 实现防回拨状态机（第五章），密钥不写死默认值。
- [ ] **Step 5** 构建时独立核对并内置发行公钥；新客户端实现设备密钥生成/DPAPI 持久化、挑战签名、认证 `trial/apply` 与 POST `latest`，**在认证版本部署前不得调用现网旧 GET `latest`**；完整 validate/吊销同步仍为目标任务。`public-key` 只供查看/核对，不得当运行时换锚接口。
- [ ] **Step 6** 定义产品过期策略（第七章）与错误文案（第八章错误码表）。
- [ ] **Step 7** 按语言接入混淆/打包保护（第三章）。
- [ ] **Step 8** 跑完整测试矩阵（第十二章），**必含**插拔 U 盘、采集失败回退、克隆机用例。
- [ ] **Step 9** 审计日志、隐私字段、密钥保管流程落地。
- [ ] **Step 10** 确认签发策略：路径 3/4 禁止自动签发付费授权（第二章 §4）。

---

## 附录 A  机器码计算（伪代码）

```text
function normalize_hw(value):
    s = trim(value)
    s = trim(s, BOM)
    if s is empty: return ""
    u = upper(s)
    if u in INVALID_SET: return ""
    return u

function probe_path12():          # 强路径，禁止 MD5 / wmic
    a = normalize(Win32_Processor.ProcessorId[0])
    b = normalize(Win32_BaseBoard.SerialNumber)
    if a and b:
        return upper_hex_sha256(utf8(upper(a + "-" + b))), 1    # 64 hex

    a = normalize(Win32_ComputerSystemProduct.UUID)
    b = normalize(Win32_BaseBoard.SerialNumber)
    if a and b:
        return upper_hex_sha256(utf8(upper(a + "-" + b))), 2

    return None, 0

function probe_path34():          # 弱路径：禁用可移动盘；禁止自动签发付费授权
    vol = volume_serial(windows_system_fixed_volume())  # 通常 C:\，禁止 U 盘/移动硬盘
    if vol:
        return format(vol, "08X"), 3

    mac = uuid.getnode()            # Python 参考；跨语言选卡规则尚未统一，始终标记弱路径
    if mac:
        return upper_hex_sha256(utf8(str(mac))), 4

    return None, 0

function get_machine_code():      # 必须含 DPAPI 缓存，防采集偶发失败
    cached = dpapi_load_strong_machine_code()  # code + path + fingerprint_ver
    live, path = probe_path12()
    if live:
        if not cached:
            dpapi_save_machine_code(live, path)
            return live
        if live == cached.code:
            if cached.path == "unknown": dpapi_upgrade_cache(live, path)
            return live
        # 硬件疑似变更：不自动改绑，继续用缓存并告警
        report_hardware_mismatch(cached, live)
        return cached.code
    if cached:
        return cached.code          # 若旧缓存 path=unknown，禁止自动申领试用
    live, path = probe_path34()
    if live:
        return live                 # 标记弱路径，仅本次使用，不写入强路径缓存
    fail("无法采集机器码")
```

**一致性要求：** 同一物理机、同一 `fingerprint_ver` 下，各端 **优先级 1 路径必须得到同一字符串**。  
历史 v1/MD5 授权与 v2/SHA-256 **机器码不同属预期**；各产品现行发行包的算法版本需逐版核对，迁移后按新机器码重签。

**稳定性要求（与第二章 §3 一致）：** 插拔 U 盘不得改变输出；路径 1/2 采集失败时回退缓存，不得跳变到路径 3/4。

**说明：** 哈希输入为 `"{cpu}-{board}"` 等 raw 串的 UTF-8；实现时不要做额外 Base64 或大小写混用。WinPilot 已全面改为 SHA-256，输出 64 位大写十六进制。

---

## 附录 B  License Token 格式

```text
Token := PREFIX "." SEG1 "." SEG2
PREFIX := <产品前缀，如 RCC1 / WPL / EPL>
SEG1  := base64url(utf8(json_payload))
SEG2  := base64url(ed25519_sign(private_key, utf8(json_payload)))
```

**解码：**

```text
pad = (4 - len(s) % 4) % 4
bytes = b64url_decode(s + "=" * pad)
```

**验签：**

```text
payload_bytes = decode(SEG1)
sig_bytes     = decode(SEG2)
ok = ed25519_verify(public_key, sig_bytes, payload_bytes)
payload = json.loads(utf8(payload_bytes))
```

**检查清单：** 分段数、PREFIX、签名、`ver`、`app_name`、`machine_code`、日期、防回拨。

**固定验签向量（仅用于自动测试；测试私钥绝不能用于生产签发）：**

```text
Ed25519 测试种子（32 字节 hex）：0707070707070707070707070707070707070707070707070707070707
公钥 SPKI DER（hex）：302a300506032b6570032100ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c
payload 原始 UTF-8（不可重排键或增加空格）：
{"ver":1,"app_name":"rust-node","machine_code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","expires_at":"2099-12-31"}
签名（64 字节 hex）：5c4589452e04d841999c6362b92fe35b77d9b2994c330033233eb5279ca819d2713486c5e9aed3191e5edcfb4b225f72e4c2d4f3d8dda968e8c0c02b1ca03c09
完整 Token：
RUSTNODE.eyJ2ZXIiOjEsImFwcF9uYW1lIjoicnVzdC1ub2RlIiwibWFjaGluZV9jb2RlIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsImV4cGlyZXNfYXQiOiIyMDk5LTEyLTMxIn0.XEWJRS4E2EGZnGNiuS_jW3fZsplMMwAzIz61J5yoGdJxNIbF6a7TGR5e3PtLIl9y5MLU89jdqWjowMArHKA8CQ
机器码强路径独立向量：raw = CPU-BOARD；SHA256(UTF-8(raw)).upper()
= 5FA02ACA9B2B02B898AA5526E916562BD29A3C881DD560666EBDDB1DE2475C03
```

此 Token 只能在测试调用中把本机码设为 64 个 `A` 才能完成机器绑定校验，**不是任何真实机器可安装的授权**。修改 payload 任一字节但保留原签名 → 签名失败；修改 PREFIX 为其他产品 → 产品匹配失败；替换机器码但不重签 → 签名失败。路径 3/4 仍需在真实 Windows 环境对照系统卷与网卡选择，不能用此强路径向量证明其跨语言一致性。

---

## 附录 C  防回拨状态格式

```json
{
  "last_run_ts": 1760000000,
  "license_id": "LIC-...",
  "expires_at": "2027-12-31",
  "sig": "<hmac_sha256_hex 或整段 DPAPI blob>"
}
```

- `sig` 必须覆盖 `last_run_ts`、`license_id`、`expires_at` 的**确定性编码**，或将整段 JSON 经 DPAPI 存储；不能只签时间戳而让其余字段可被改写。
- 读取后校验 `sig`；失败 = 篡改。
- 更新策略见第五章状态机；`last_run_ts` 只增不减。

---

## 附录 D  标准客户端接口签名

```text
# 机器码
get_machine_code() -> str                    # 必须含 DPAPI 缓存与弱路径标记
get_machine_code_info() -> {code, path, from_cache}   # path: 1|2|3|4；旧缓存无来源时为 unknown

# Token
parse_token(text) -> (prefix, payload_dict, sig_bytes)
verify_signed_license(text) -> (ok: bool, msg: str, payload: dict | None)

# 存储
install_license(text) -> (ok, msg)
get_installed_license() -> str
get_license_status() -> StatusDict

# 试用与网络
request_trial_license() -> (ok, msg, data)
fetch_public_key() -> str
validate_online() -> (ok, status)

# 启动
ensure_license(silent: bool) -> bool
```

`StatusDict` 至少含：`installed, valid, message, machine_code, license_id, expires_at, edition, features`。

---

## 附录 E  错误码与用户文案（默认中文）

| code | 默认文案 |
| --- | --- |
| `MACHINE_MISMATCH` | 机器码不匹配，该授权不属于本机 |
| `EXPIRED` | 授权已过期 |
| `NOT_BEFORE` | 授权尚未生效 |
| `SIGNATURE_INVALID` | 授权签名无效 |
| `REVOKED` | 授权已被吊销，请联系供应商 |
| `TIME_ROLLBACK` | 系统时间异常，禁止回退 |
| `ACTIVATION_LIMIT` | 激活次数已达上限 |
| `SERVICE_UNAVAILABLE` | 授权服务暂不可用（不影响已激活授权） |
| `LICENSE_REQUIRED` | 需要有效授权后才能使用该功能 |
| `STATE_TAMPERED` | 授权状态被篡改 |
| `NO_LICENSE` | 未提供授权码 |

激活页必须展示 **机器码** 与 **一键复制**；失败时保留输入框内容便于重试。

---

## 附录 F  密钥管理与发布流程

| 角色 | 职责 |
| --- | --- |
| 签发环境 | 持有 Ed25519 私钥；签发 Token；写审计 |
| 客户端构建 | 写入公钥；注入产品 `APP_NAME`/`APP_PREFIX`；混淆打包 |
| 轮换 | 双公钥窗口 → 切换签发私钥 → 下线旧私钥 |

发布前核对：

- [ ] 安装包内无私钥、无生产 HMAC 密钥；
- [ ] 公钥指纹与签发端一致；
- [ ] `app_name` / 前缀与服务端签发配置一致；
- [ ] 试用策略、宽限期与产品页文案一致。
- [ ] 安装包进行代码签名，校验发布者与哈希；所用安装器的商业授权已核实；
- [ ] 在干净机器跑完第十二章适用用例，并记录不能通过的目标接口/轮换用例。

---

## 附录 G  与现有三端对照（演进参考）

| 能力 | RCC | WinPilot | E-Player | 本规范 |
| --- | --- | --- | --- | --- |
| 签名 | Ed25519 `RCC1` | Ed25519 `WPL` | Ed25519 `EPL` | Ed25519，统一格式 |
| 机器码 | v1/v2 存量待核验 | v2/SHA-256 + DPAPI 缓存 | v1/v2 存量待核验 | 新项目强制 v2/SHA-256 |
| 存储 | SQLite 明文 | DPAPI 双写 | config 明文 | DPAPI 双写 |
| 防回拨 | HMAC last_run | HTTP Date + 300s | 无 | 签名状态 + 可信时间 |
| 试用 | 服务端 1 年 | 本地 10 分钟 | 无 UI | 服务端为主 |
| 周期校验 | 4h 线程 | 仅启动 | 仅启动 | 3–7 天后台 + 启动 |
| 网络恢复 | 公钥热更 | — | 试用接口未接线 | 现网接口 + 目标 API |

历史债（新项目禁止；三端已按本规范改造的项可勾掉）：

1. ~~WMIC 依赖~~（E-Player 已改为 CIM）；
2. fallback 到与主算法不同的第三方 ID（E-Player 已移除 node-machine-id 回退）；
3. 授权明文进普通配置/SQLite 而无 DPAPI（机器码已 DPAPI 缓存；授权码存储仍待统一包装）；
4. ~~HMAC/状态密钥硬编码默认值~~（RCC 运行期生成；E-Player 可用环境变量覆盖）；
5. 无防回拨（E-Player 已补签名状态 + 300s 容差）；
6. 试用函数写好但 UI 未接线（E-Player 已暴露 `license:trial` IPC）；
7. **机器码使用 MD5**（历史 v1 授权须逐产品盘点；迁移 v2 后受影响旧授权需重签，不能仅凭本表认定所有现网发行包已迁移）。

---

## 附录 H  Rust Node 产品落地页（现状与待办）

本附录是产品快照，不改变前文通用目标规范；**“现有”不等于“通过生产验收”**。实现或服务端配置变化时必须同步更新，不得用目标接口的描述代替现网联调证据。

| 项 | 当前实现/约定 | 上线前需确认 |
| --- | --- | --- |
| 产品标识 | 客户端 `APP_NAME=rust-node`、`APP_PREFIX=RUSTNODE`、`fingerprint_ver=2` | 核对 license-service 的 `TOKEN_PREFIXES` 注册与试用天数上限 |
| 试用 | 路径 1/2 自动申请 365 天；弱路径不自动申请；本地短试用默认关闭 | 新机器核对实际签发天数、一机一次及错误码 |
| 授权策略 | `LICENSE_ENFORCE=block` 为默认；`warn` 只用于开发诊断 | 商用部署不得把 warn 当授权门禁 |
| 公钥 | release 构建期提供发行方 PEM 并嵌入二进制；安装目录公钥文件不参与正式版信任决策 | 核对指纹、签发私钥匹配；公钥轮换/双公钥尚未实现 |
| 存储 | 程序在 `%LOCALAPPDATA%\Programs\RustNode`；密码、会话密钥、授权和工作流在 `%LOCALAPPDATA%\RustNode`；授权/防回拨状态使用文件+HKCU | 完成删除单侧副本/损坏副本/多用户/重装测试；现有注册表共用 `updated_at` 且文件使用修改时间，未达到 §4 要求的每条记录独立更新时间和“先校验再择优” |
| 升级 | 首次运行只复制旧便携版的数据，不删除旧文件；卸载保留用户数据 | 测试旧授权恢复、升级覆盖、卸载重装和数据备份 |
| 网络续期 | 已部署版本的旧 GET `latest` 仍只凭机器码；客户端约每 6h 拾取 | 本仓库 POST 版已增加设备签名认证；需服务端上线并升级客户端，HTTP 404 不能作为吊销证据 |
| 吊销与离线 | 已有本地吊销标记；断网时本地未到期授权继续有效 | 明确服务器吊销最大延迟及离线无法即时吊销的风险 |
| 弱机器码 | 强路径缓存可回退；弱路径不自动领取试用 | 路径 3 的非 C: 系统卷、路径 4 与 Python `uuid.getnode()` 的选卡一致性尚未验证，需实机对拍或只保留人工审核 |
| 公钥热更 | 不在正式版中接受未经旧信任锚认证的新公钥 | 目标 §9 的轮换清单和多公钥窗口需单独开发并联调 |
| Web 门禁 | 未登录请求为 401；来源异常为 403；`block` 模式业务 API 返回 503；授权/认证/健康路径豁免；WebSocket 受登录和授权检查 | 持续连接、跨站请求、到期与续期恢复做真实浏览器验收 |
| 安装包 | Inno Setup 按用户安装的 x64 测试包；前端 JS 随包可见，二进制不能保证不可逆向 | 实机安装测试、Authenticode 签名、安装器商业使用许可；不得以混淆替代服务端信任边界 |

**产品发布阻断项：** 设备认证版接口的实际部署与 Windows 客户端对接、`latest` 404 与真实吊销的区分、公钥轮换策略（如计划轮换）、第十二章适用的干净机器测试、历史凭据轮换和安装包签名/许可。可以先做受控安装试点，但不得将未完成项写成已上线或“授权完全闭环”。

---

*文档结束。实现有偏离时，先改本文再改代码；未覆盖的场景提交 PR 更新附录。*
