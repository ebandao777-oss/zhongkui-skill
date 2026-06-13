#!/usr/bin/env python3
"""钟馗 Skill 安全审查引擎 - 主入口

用法:
    python zhongkui.py <skill目录路径> [--quick]

    --quick  仅执行 Layer 1 静态审计（秒级完成）
"""

import sys
import os
from pathlib import Path

# 将当前目录加入路径以便导入 core 子模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.auditor import Auditor
from core.scorer import Scorer


def main():
    if len(sys.argv) < 2:
        print("用法: python zhongkui.py <skill目录路径> [--quick]")
        print()
        print("示例:")
        print("  python zhongkui.py ./my-skill")
        print("  python zhongkui.py ./my-skill --quick")
        sys.exit(1)
    
    target_path = Path(sys.argv[1]).resolve()
    quick_mode = "--quick" in sys.argv
    
    if not target_path.exists():
        print(f"错误: 路径不存在 - {target_path}")
        sys.exit(1)
    
    if not target_path.is_dir():
        print(f"错误: 不是目录 - {target_path}")
        sys.exit(1)
    
    # 执行 Layer 1 静态审计
    auditor = Auditor(target_path)
    auditor.run_full()
    
    # 评分
    scorer = Scorer()
    final_score, verdict, flags = scorer.compute(auditor)
    
    # 输出报告
    print_report(auditor, final_score, verdict, flags, quick_mode)


def print_report(audit, score, verdict, flags, quick_mode):
    """输出 Markdown 格式审查报告 —— 与 SKILL.md 强制输出格式一致"""
    icon_map = {"clean": "✅", "suspicious": "⚠️", "malicious": "🚫"}
    icon = icon_map.get(verdict, "❓")
    
    print(f"## 钟馗裁定：[{icon}]")
    print(f"**总分**：{score} / 100")
    print(f"**一句话**：{audit.summary}")
    print()
    
    # 一票否决判定
    veto_hits = audit.get_veto_hits()
    if veto_hits:
        print("### 🚫 一票否决项（命中即判恶）")
        print("| 红线 | 命中内容 | 文件:行号 |")
        print("|:---|:---|:---|")
        for v in veto_hits:
            content = v['content'][:60]
            print(f"| {v['rule']} | {content} | {v['file']}:L{v['line']} |")
        print()
        print("> 命中一票否决项，直接裁定 🚫 恶意。修复后方可重新审查。")
        print()
        return
    
    # 即时拒绝红线
    redline_hits = audit.get_redline_hits()
    if redline_hits:
        print("### 🔴 即时拒绝红线")
        print("| 红线 | 命中内容 | 文件:行号 |")
        print("|:---|:---|:---|")
        for r in redline_hits:
            print(f"| {r['rule']} | {r['content']} | {r['file']}:L{r['line']} |")
        print()
        print("> 命中即时拒绝红线，直接裁定 🚫 恶意。修复后方可重新审查。")
        print()
        return
    
    # 扣分项
    deductions = audit.get_deductions()
    if deductions:
        print("### 扣分项")
        print("| 层级 | 检查项 | 风险类型 | 扣分 | 命中内容（行号） |")
        print("|:---|:---|:---|:---|:---|")
        for d in deductions:
            content = d.get('content', '')[:50]
            line_info = f"{d['file']}:L{d['line']}" if d.get('line') else d['file']
            print(f"| L1 | {d['check']} | {d['risk']} | -{d['points']} | {line_info} |")
        print()
    
    # 审计覆盖统计
    stats = audit.get_stats()
    print("### 审计覆盖")
    print(f"- 文件数：{stats['files_scanned']}")
    print(f"- 检查项：{stats['checks_total']}（命中 {stats['checks_hit']}，通过 {stats['checks_pass']}）")
    print()
    
    # 模式标识
    if quick_mode:
        print("> 模式：快速审计（仅 Layer 1）。完整审计请去掉 --quick 参数。")
    
    # 结论
    print(f"> 审查完成。裁定：{icon} {verdict.upper()}")


if __name__ == "__main__":
    main()
