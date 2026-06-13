# 论文映射表

> 摘自 [Agent Skill 安全审查方法论](agent-skill-security-review.md)，第8章

---

| 方案模块 | 对应论文 | 借鉴内容 |
|:---|:---|:---|
| 风险分类（8 维） | Snyk ToxicSkills, CSA | 风险分类体系 + 审计数据 |
| 三层审查架构 | Design Patterns 2025, Snyk | 纵深防御分层 |
| 静态检查清单 | Greshake 2023, CSA, Snyk, MiniScope | 检测模式与关键词 |
| 行为模拟评估 | ToolEmu | LM 模拟沙箱 + 自动评估器 |
| 最小权限推导 | MiniScope | 权限层级重建算法 |
| 供应链溯源 | CSA, AgentPoison | 依赖审计 + 威胁情报联动 |
| 扫描器一致性 | OpenClaw+NVIDIA | 多引擎交叉验证 + 分歧升级 |
| 权限门控机制 | Design Patterns 2025, MiniScope | 用户确认 / 沙箱化 |
