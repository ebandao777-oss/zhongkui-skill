---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: f114db32c8f49bbd4c4c544cd9de808d_9573e92166f911f1a0095254002afed2
    ReservedCode1: WQhxj+PgXtiXJpiQCG2nC7ZkttSYuH21j4pStTF7JrT1ANu0Zf/9DKp6rA3wD+S93wgJcBlk/G2nnk6mMJ13k8JhssTxgSpQ3wetooBQhqAPPFykY11LZW0jCBX0iRrxqMdraPmsJcrMVb4gD9AtLr9abbX5l4yOJyV6rL0TalwCnmiHW3D9KL/Ul9Y=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: f114db32c8f49bbd4c4c544cd9de808d_9573e92166f911f1a0095254002afed2
    ReservedCode2: WQhxj+PgXtiXJpiQCG2nC7ZkttSYuH21j4pStTF7JrT1ANu0Zf/9DKp6rA3wD+S93wgJcBlk/G2nnk6mMJ13k8JhssTxgSpQ3wetooBQhqAPPFykY11LZW0jCBX0iRrxqMdraPmsJcrMVb4gD9AtLr9abbX5l4yOJyV6rL0TalwCnmiHW3D9KL/Ul9Y=
---

# 钟馗.Skill 快速上手

> 直来直去，三步上手。

## 安装

把 `zhongkui-skill/` 目录放入 skills 目录即可。

## 基本用法

### 全量审查

```
审 E:\skills\some-skill
```

执行完整三层审查（52 项静态 + 18 场景行为模拟 + 8 维溯源），输出结构化裁定报告。

### 快速审计（秒级）

```
快审 E:\skills\some-skill
```

仅 Layer 1 静态审计（52 项），秒级完成，适合批量初筛。

### 直接运行脚本

```bash
# 完整审计
python zhongkui.py E:\skills\some-skill

# 快速审计（仅 Layer 1）
python zhongkui.py E:\skills\some-skill --quick
```

### 只查依赖

```
审依赖 E:\skills\some-skill
```

仅 Layer 3 供应链溯源：8 维溯源（发布者信誉 / CVE 依赖 / 版本变更 / 社区反馈 / SBOM / 外部 API 安全评估 / SDK 安全准入 / 熔断与降级预案）。

### 只查行为

```
审行为 E:\skills\some-skill
```

仅 Layer 2 行为模拟：18 个攻击场景 + 红队对抗验证（OWASP Top 10 for LLM 专项测试矩阵），适合深度复查。

## 输出解读

| 裁定 | 含义 | 行动 |
|:---|:---|:---|
| ✅ 干净 | ≥ 85 分 | 放心装 |
| ⚠️-low | 70-84 分 | 低风险可疑，看一眼扣分项再决定 |
| ⚠️-high | 60-69 分 | 高危可疑，建议拒绝 |
| 🚫 恶意 | < 60 或命中否决 | 别装，上报 |

评分由三层加权计算：Layer 1 静态审计（W1=0.35） + Layer 2 行为模拟（W2=0.55） + 数据安全声明（W3=0.10），Layer 3 额外扣分 0-30。红队对抗测试通过率 < 95% 自动阻断。

## 常见问题

**Q: 为什么我的 Skill 被判 R8？**
A: 八成是 SKILL.md 里有零宽字符。用 `审` 命令会告诉你具体行号。

**Q: 审查多久？**
A: Layer 1 秒级。Layer 2 约 30 秒（18 场景模拟）。Layer 3 取决于依赖数量。

**Q: 新增了哪些风险类型？**
A: v1.0 新增 R9（数据泄露与隐私违规）和 R10（有害输出与内容合规），检查项从 30 扩展到 52 项。

**Q: 脚本和对话审查有什么区别？**
A: 脚本只执行 Layer 1 静态审计；对话中使用 Skill 可执行完整三层审查（含行为模拟和供应链溯源）。

**Q: 黄标为什么有 high/low 之分？**
A: 60-69 分为高危可疑（⚠️-high），建议拒绝；70-84 分为低风险可疑（⚠️-low），附带主要风险点供你判断。

**Q: 误报怎么办？**
A: 记下扣分项的具体内容，反馈给钟馗。多引擎仲裁机制保证不会单一规则误杀。
*（内容由AI生成，仅供参考）*
