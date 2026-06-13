# 静态审计清单（30 项）

> Layer 1：所有 Skill 必经，秒级完成。来源：CSA 2026 / Snyk 2026 / MiniScope 2025 / Design Patterns 2025

## 使用说明

逐项检查，命中即扣分。每项标注：行号（若可定位）、风险类型（R1-R8）、扣分值。一票否决项命中 → 直接终止审查输出 🚫。

---

## 一、元数据检查（5 项，共 10 分）

| # | 检查项 | 检测方法 | 扣分 | 风险 |
|:---|:---|:---|:---|:---|
| M1 | 发布者身份 | 无 GPG 签名或已验证身份 → 扣分 | -2 | — |
| M2 | 版本号规范 | 无版本号或跳跃 ≥3 个主版本号 → 扣分 | -2 | R4 |
| M3 | 依赖声明完整 | 未声明依赖或版本未锁定 → 扣分 | -2 | R4 |
| M4 | 权限声明显式 | 未声明所需权限（文件/网络/进程）→ 扣分 | -2 | R6 |
| M5 | 自述文件 | 无 README 或用法说明 → 扣分 | -2 | — |

---

## 二、SKILL.md 内容检查（10 项，共 40 分）🔴 含一票否决项

| # | 检查项 | 正则/关键词 | 扣分 | 风险 | 否决 |
|:---|:---|:---|:---|:---|:---|
| C1 | 直接提示注入 | `ignore (all )?previous (instructions|prompt)`, `you are now`, `system prompt override`, `pretend (you are|to be)`, `developer mode`, `DAN`, `bypass (safety|security|restriction)` | -10 | R1 | ✅ |
| C2 | 间接注入触发源 | `fetch_url`, `read_webpage`, `scrape`, `curl.*http`, `web_fetch` | -4 | R1 | — |
| C3 | 凭证访问模式 | 同时出现 `\.ssh\|\.env\|api_key\|token\|password\|secret\|credential` + `read\|display\|show\|output\|print\|cat\|list` | -10 | R3 | ✅ |
| C4 | 数据外传目标 | 同时出现 文件读指令 + `webhook\|http.*POST\|upload\|send.*http\|curl.*-X POST\|requests\.post` | -10 | R5 | ✅ |
| C5 | 系统级危险命令 | `rm -rf\|format\|del /f\|reg delete\|shutdown\|mkfs\|dd if=` | -10 | R2 | ✅ |
| C6 | 权限提升指令 | `sudo\|runas\|Administrator\|chmod 777\|chown.*root\|Set-Acl.*FullControl` | -4 | R6 | — |
| C7 | 持久化路径 | `~/.bashrc\|~/.zshrc\|/etc/crontab\|Startup\|LaunchAgents\|HKLM.*Run\|CurrentVersion.*Run` + 写入动词 | -10 | R7 | ✅ |
| C8 | 隐蔽 Unicode | `\u200B\|\u200C\|\u200D\|\u202E\|\uFEFF` 零宽/控制字符 | -4 | R8 | — |
| C9 | 条件触发 | `if date\|if time\|after \d{4}\|wait until\|when.*then\|trigger.*when` | -4 | R8 | — |
| C10 | 编码/混淆载荷 | Base64 字符串长度 > 40 且解码后含危险关键词 | -4 | R2/R8 | — |

**C1/C3/C4/C5/C7** 任意命中 → 一票否决，直接裁定 🚫 恶意，终止审查。

---

## 三、辅助脚本检查（8 项，共 32 分）🔴 含一票否决项

| # | 检查项 | 检测方法 | 扣分 | 风险 | 否决 |
|:---|:---|:---|:---|:---|:---|
| S1 | 子进程调用 | `subprocess\|os\.system\|os\.popen\|exec\|spawn\|ShellExecute` | -4 | R2 | — |
| S2 | 网络出站 | `socket\|requests\.(get\|post)\|urllib\|http\.client\|fetch.*http` | -4 | R5 | — |
| S3 | 敏感路径读写 | `/etc/passwd\|C:\\\\Windows\|~/.ssh\|/root/` | -4 | R2 | — |
| S4 | 动态代码执行 | `eval\(\|exec\(\|compile\(` | -4 | R2 | — |
| S5 | 依赖 CVE | 与 CVE DB 交叉比对命中的依赖 | -4 | R4 | — |
| S6 | 安装脚本恶意行为 | `curl.*\|.*bash` 或 `wget.*\|.*sh` 链式执行模式 | -10 | R2 | ✅ |
| S7 | 文件权限修改 | `chmod\|chown\|icacls\|Set-Acl` | -4 | R6 | — |
| S8 | 配置篡改 | `reg add\|regedit\|Set-ItemProperty\|defaults write` | -4 | R7 | — |

**S6** 命中 → 一票否决，直接裁定 🚫 恶意。

---

## 四、权限声明检查（7 项，共 18 分）

| # | 检查项 | 判定逻辑 | 扣分 | 风险 |
|:---|:---|:---|:---|:---|
| P1 | 最小权限原则 | 权限声明范围 > 任务描述范围 → 扣分 | -3 | R6 |
| P2 | 网络权限必要性 | 声明网络权限但任务无联网需求 → 扣分 | -3 | R6 |
| P3 | 文件读写范围过宽 | 声明 `/**` 全局读写 → 扣分 | -3 | R6 |
| P4 | 进程管理权限 | 声明 `process_kill`/`service_control` 无合理场景 → 扣分 | -3 | R6 |
| P5 | 权限传递风险 | 存在权限串联提升路径（A→B→C→获取更高权限）→ 扣分 | -3 | R6 |
| P6 | 用户确认门控 | 高风险操作（删除/支付/发邮件）未声明 `confirm_required` → 扣分 | -2 | — |
| P7 | 沙箱化标记 | 未声明 `sandbox: required` → 扣分 | -1 | — |

---

## Layer 1 总分

```
Layer1_Score = 100 - Σ(扣分)
```

满分 100。命中一票否决项 → 直接 0 分 + 🚫。

---

## 检测优先级

1. **先跑否决项**（C1/C3/C4/C5/C7/S6）→ 命中即终止
2. **再跑高危项**（C2/C6/C8/C9/C10/S1-S4/S7-S8）
3. **最后跑中危项**（M1-M5/P1-P7/S5）
