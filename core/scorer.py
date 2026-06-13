"""钟馗评分计算器"""


class Scorer:
    """综合评分与裁定 — 依据 references/scoring.md 公式"""
    
    # 权重
    W1 = 0.35  # Layer 1 静态审计
    W2 = 0.55  # Layer 2 行为模拟（离线默认满分）
    W3 = 0.10  # 数据安全声明
    
    def compute(self, audit_result):
        """
        计算总分并返回 (score, verdict, flags)
        
        参数:
            audit_result: Auditor 实例（已执行 run_full()）
        
        返回:
            (score: float, verdict: str, flags: dict)
            verdict: "clean" / "suspicious" / "malicious"
        """
        # 一票否决判定
        veto_hits = audit_result.get_veto_hits()
        if veto_hits:
            return (0, "malicious", {"veto": True, "veto_count": len(veto_hits)})
        
        # 即时拒绝红线判定
        redline_hits = audit_result.get_redline_hits()
        if redline_hits:
            return (0, "malicious", {"redline": True, "redline_count": len(redline_hits)})
        
        hits = audit_result.get_deductions()
        
        # Layer 1 分数：满分 100，每项扣分累加
        total_penalty = sum(h.get('points', 0) for h in hits if not h['check'].startswith('D'))
        l1_score = max(0, 100 - total_penalty)
        
        # Layer 2 离线时默认满分（行为模拟需运行时环境介入）
        l2_score = 100
        
        # 数据安全得分（D1-D7 共 7 项，每项满分约 14.3）
        d_count = sum(1 for h in hits if h['check'].startswith('D'))
        d_score = max(0, 100 - d_count * 14.3)
        
        # 综合加权
        final = round(l1_score * self.W1 + l2_score * self.W2 + d_score * self.W3, 1)
        
        # 裁定阈值
        if final >= 85:
            return (final, "clean", {})
        elif final >= 60:
            return (final, "suspicious", {})
        else:
            return (final, "malicious", {})
