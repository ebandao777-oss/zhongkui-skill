"""钟馗 Layer 1 静态审计引擎 - 52 项检查"""

import re
from pathlib import Path
from typing import List, Dict, Any


class Auditor:
    """Layer 1 静态审计引擎 - 基于 14 篇前沿论文的 52 项检查"""
    
    # 一票否决风险类型
    VETO_RISKS = {"R1", "R2", "R3", "R5", "R7"}
    
    def __init__(self, skill_path: Path):
        self.skill_path = skill_path
        self.files = {}  # filename -> content_lines
        self.hits = []   # 所有命中记录（扣分项）
        self.veto_items = []  # 一票否决命中
        self.summary = ""  # 一句话总结
    
    def run_full(self) -> 'Auditor':
        """执行完整 52 项静态审计"""
        self._load_files()
        self._check_metadata()       # M1-M7
        self._check_skill_content()  # C1-C15
        self._check_scripts()        # S1-S12
        self._check_permissions()    # P1-P11
        self._check_data_security()  # D1-D7
        self._gen_summary()
        return self
    
    def _load_files(self):
        """加载目标目录下所有可审计文本文件"""
        for f in self.skill_path.rglob("*"):
            if f.name.startswith('.') and 'SKILL.md' not in f.name:
                continue
            if f.is_file() and f.suffix.lower() in {'.md', '.py', '.sh', '.js', '.json', '.yaml', '.yml', '.txt', '.bat', '.ps1'}:
                try:
                    with open(f, 'r', encoding='utf-8', errors='ignore') as fh:
                        rel = str(f.relative_to(self.skill_path))
                        self.files[rel] = fh.readlines()
                except Exception:
                    pass
    
    def _check_metadata(self):
        """3.1 元数据检查 M1-M7"""
        skill_md = "SKILL.md"
        lines = self.files.get(skill_md, [])
        full_text = "".join(lines)
        
        # M1: 发布者身份验证
        if not re.search(r'author:', full_text, re.IGNORECASE):
            self.hits.append({"check": "M1", "risk": "R6", "points": 5, "file": skill_md,
                            "content": "无发布者身份声明", "line": 0, "flag": "publisher_unverified"})
        
        # M2: 版本号规范
        if not re.search(r'version:', full_text, re.IGNORECASE):
            self.hits.append({"check": "M2", "risk": "R6", "points": 3, "file": skill_md,
                            "content": "无版本号声明", "line": 0, "flag": "version_anomaly"})
        
        # M3: 依赖声明完整
        py_files = [fn for fn in self.files if fn.endswith('.py')]
        has_deps_file = any(fn in self.files for fn in ['requirements.txt', 'package.json'])
        has_deps_decl = bool(re.search(r'dependencies|依赖|requirements', full_text, re.IGNORECASE))
        if py_files and not has_deps_file and not has_deps_decl:
            self.hits.append({"check": "M3", "risk": "R4", "points": 3, "file": skill_md,
                            "content": "有脚本但未声明依赖", "line": 0, "flag": "deps_undeclared"})
        
        # M4: 权限声明显式
        if not re.search(r'permission|权限|sandbox', full_text, re.IGNORECASE):
            self.hits.append({"check": "M4", "risk": "R6", "points": 5, "file": skill_md,
                            "content": "未声明所需权限", "line": 0, "flag": "permission_implicit"})
        
        # M5: 自述文件存在
        if 'README.md' not in self.files:
            self.hits.append({"check": "M5", "risk": "-", "points": 5, "file": "README.md",
                            "content": "无 README 文件", "line": 0, "flag": "no_readme"})
        
        # M6: 数据声明完整
        if not re.search(r'数据.*收集|数据.*缓存|data.*collect|data.*policy|隐私|privacy', full_text, re.IGNORECASE):
            self.hits.append({"check": "M6", "risk": "R9", "points": 3, "file": skill_md,
                            "content": "未声明数据处理策略", "line": 0, "flag": "data_policy_missing"})
        
        # M7: 合规声明存在
        if not re.search(r'GDPR|PIPL|合规|compliance', full_text, re.IGNORECASE):
            self.hits.append({"check": "M7", "risk": "R9", "points": 2, "file": skill_md,
                            "content": "无合规框架声明", "line": 0, "flag": "compliance_undeclared"})
    
    def _check_skill_content(self):
        """3.2 SKILL.md 内容检查 C1-C15"""
        skill_md = "SKILL.md"
        lines = self.files.get(skill_md, [])
        full_text = "".join(lines)
        
        # C1: 直接提示注入模式（命中=一票否决）
        injection_patterns = [
            (r'ignore\s+(all\s+)?(previous|prior)\s+instructions?', '提示注入: ignore instructions'),
            (r'you\s+are\s+now\s+(a\s+)?(jailbreak|uncensored|unfiltered)', '提示注入: you are now'),
            (r'system\s+prompt\s+override', '提示注入: system prompt override'),
            (r'pretend\s+you\s+(are|have)\s+no\s+(restrictions|limitations|rules)', '提示注入: pretend no rules'),
            (r'DAN\s+mode|developer\s+mode', '提示注入: DAN/developer mode'),
            (r'忘记.*(指令|规则|限制)|forget.*(instruction|rule)', '提示注入: forget instructions'),
            (r'你不.*(受|遵守|服从).*(限制|规则|指令)', '提示注入: 中文绕过指令'),
        ]
        for pattern, desc in injection_patterns:
            for i, line in enumerate(lines):
                if re.search(pattern, line, re.IGNORECASE):
                    self.veto_items.append({"rule": "C1: " + desc, "content": line.strip(), "file": skill_md, "line": i+1})
        
        # C2: 间接注入触发源
        indirect_patterns = [r'fetch_url', r'read_webpage', r'curl.*http', r'wget.*http']
        for i, line in enumerate(lines):
            for pat in indirect_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    self.hits.append({"check": "C2", "risk": "R1", "points": 5, "file": skill_md,
                                    "content": line.strip(), "line": i+1, "flag": "indirect_injection_source"})
        
        # C3: 凭证访问模式
        cred_patterns = [r'\.env\b', r'\.ssh\b', r'api_key', r'api\s*key', r'token\s*=',
                        r'password\s*=', r'secret\s*key', r'credential']
        for i, line in enumerate(lines):
            for pat in cred_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    self.hits.append({"check": "C3", "risk": "R3", "points": 8, "file": skill_md,
                                    "content": line.strip(), "line": i+1, "flag": "credential_access"})
        
        # C4: 数据外传目标
        exfil_patterns = [(r'https?://\S+', '外传 URL'), (r'webhook', 'webhook'),
                         (r'curl\s+.*POST', 'curl POST'), (r'requests\.post', 'requests.post')]
        for i, line in enumerate(lines):
            for pat, desc in exfil_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    self.hits.append({"check": "C4", "risk": "R5", "points": 8, "file": skill_md,
                                    "content": f"{desc}: {line.strip()}", "line": i+1, "flag": "data_exfiltration_target"})
        
        # C5: 系统级危险命令（命中=一票否决）
        danger_patterns = [r'rm\s+-rf\s+/', r'format\s+[cdf]', r'del\s+/[fq]',
                          r'reg\s+delete', r'shutdown', r'dd\s+if=', r'mkfs\.']
        for i, line in enumerate(lines):
            for pat in danger_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    self.veto_items.append({"rule": "C5: 系统危险命令", "content": line.strip(),
                                            "file": skill_md, "line": i+1})
        
        # C6: 权限提升指令
        priv_patterns = [r'sudo\b', r'runas\b', r'Administrator', r'chmod\s+777', r'root:']
        for i, line in enumerate(lines):
            for pat in priv_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    self.hits.append({"check": "C6", "risk": "R6", "points": 5, "file": skill_md,
                                    "content": line.strip(), "line": i+1, "flag": "privilege_escalation"})
        
        # C7: 持久化写入路径（命中=一票否决）
        persist_patterns = [r'~/.bashrc', r'/etc/crontab', r'Startup', r'LaunchAgents',
                           r'~/.zshrc', r'/etc/systemd']
        for i, line in enumerate(lines):
            for pat in persist_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    self.veto_items.append({"rule": "C7: 持久化写入", "content": line.strip(),
                                            "file": skill_md, "line": i+1})
        
        # C8: 隐蔽 Unicode 字符
        unicode_danger = ['\u200b', '\u200c', '\u200d', '\u200e', '\u200f',
                         '\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
                         '\u2060', '\u2061', '\u2062', '\u2063', '\ufeff']
        for i, line in enumerate(lines):
            for uc in unicode_danger:
                if uc in line:
                    self.hits.append({"check": "C8", "risk": "R8", "points": 10, "file": skill_md,
                                    "content": f"含隐蔽Unicode字符 U+{ord(uc):04X}", "line": i+1,
                                    "flag": "unicode_conceal"})
        
        # C9: 条件触发逻辑
        time_patterns = [r'if\s+date', r'if\s+time', r'after\s+\d{4}',
                        r'wait\s+until', r'when\s+clock', r'schedule.*trigger']
        for i, line in enumerate(lines):
            for pat in time_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    self.hits.append({"check": "C9", "risk": "R8", "points": 5, "file": skill_md,
                                    "content": line.strip(), "line": i+1, "flag": "conditional_trigger"})
        
        # C10: 混淆/编码内容
        obfusc_patterns = [r'base64', r'eval\s*\(', r'exec\s*\(', r'compile\s*\(']
        for i, line in enumerate(lines):
            for pat in obfusc_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    self.hits.append({"check": "C10", "risk": "R8", "points": 5, "file": skill_md,
                                    "content": line.strip(), "line": i+1, "flag": "obfuscated_code"})
        
        # C11: 参数校验缺失
        if re.search(r'user_input|args|argv|param', full_text, re.IGNORECASE):
            if not re.search(r'validate|sanitize|校验|验证|过滤', full_text, re.IGNORECASE):
                self.hits.append({"check": "C11", "risk": "R2", "points": 3, "file": skill_md,
                                "content": "有参数接收但无校验逻辑", "line": 0, "flag": "no_input_validation"})
        
        # C12: 上下文污染源
        ctx_patterns = [r'conversation_history', r'chat_context', r'previous_messages',
                       r'对话历史', r'历史消息']
        for i, line in enumerate(lines):
            for pat in ctx_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    self.hits.append({"check": "C12", "risk": "R1", "points": 3, "file": skill_md,
                                    "content": line.strip(), "line": i+1, "flag": "context_pollution_risk"})
        
        # C13: 输出安全风险
        output_patterns = [r'generate\s', r'output\s+response', r'reply\s+to', r'生成.*回复']
        has_filter = bool(re.search(r'filter|过滤|safety|审核|moderat', full_text, re.IGNORECASE))
        for i, line in enumerate(lines):
            for pat in output_patterns:
                if re.search(pat, line, re.IGNORECASE) and not has_filter:
                    self.hits.append({"check": "C13", "risk": "R10", "points": 3, "file": skill_md,
                                    "content": "有输出路径但无内容过滤", "line": i+1, "flag": "unfiltered_output"})
                    break
        
        # C14: 版权复述风险
        copyright_patterns = [r'reproduce', r'copy_full_text', r'verbatim', r'完整.*输出', r'全部.*复制']
        for i, line in enumerate(lines):
            for pat in copyright_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    self.hits.append({"check": "C14", "risk": "R10", "points": 3, "file": skill_md,
                                    "content": line.strip(), "line": i+1, "flag": "copyright_risk"})
        
        # C15: 模型边界模糊
        roleplay_patterns = [r'you are now\b', r'act as\b', r'roleplay', r'扮演', r'假设你是']
        for i, line in enumerate(lines):
            for pat in roleplay_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    self.hits.append({"check": "C15", "risk": "R1", "points": 3, "file": skill_md,
                                    "content": line.strip(), "line": i+1, "flag": "roleplay_override"})
    
    def _check_scripts(self):
        """3.3 辅助脚本检查 S1-S12"""
        script_exts = {'.py', '.sh', '.js', '.bat', '.ps1'}
        script_files = {fn: content for fn, content in self.files.items()
                       if Path(fn).suffix.lower() in script_exts}
        
        for fn, lines in script_files.items():
            full_text = "".join(lines)
            
            # S1: 子进程调用
            for pat in [r'subprocess', r'os\.system', r'os\.exec', r'os\.spawn', r'child_process']:
                for i, line in enumerate(lines):
                    if re.search(pat, line, re.IGNORECASE):
                        self.hits.append({"check": "S1", "risk": "R2", "points": 5, "file": fn,
                                        "content": line.strip(), "line": i+1, "flag": "subprocess_call"})
            
            # S2: 网络出站连接
            for pat in [r'socket\.', r'requests\.', r'urllib', r'http\.client', r'fetch\(']:
                for i, line in enumerate(lines):
                    if re.search(pat, line, re.IGNORECASE):
                        self.hits.append({"check": "S2", "risk": "R5", "points": 5, "file": fn,
                                        "content": line.strip(), "line": i+1, "flag": "network_egress"})
            
            # S3: 文件系统敏感路径
            for pat in [r'/etc/passwd', r'C:\\Windows', r'~/.ssh', r'/etc/shadow']:
                for i, line in enumerate(lines):
                    if re.search(pat, line):
                        self.hits.append({"check": "S3", "risk": "R3", "points": 8, "file": fn,
                                        "content": line.strip(), "line": i+1, "flag": "sensitive_path"})
            
            # S4: 动态代码执行
            for pat in [r'eval\s*\(', r'exec\s*\(', r'compile\s*\(', r'Function\s*\(']:
                for i, line in enumerate(lines):
                    if re.search(pat, line):
                        self.hits.append({"check": "S4", "risk": "R2", "points": 8, "file": fn,
                                        "content": line.strip(), "line": i+1, "flag": "dynamic_exec"})
            
            # S5: 依赖版本漏洞标记
            if fn in ['requirements.txt']:
                for i, line in enumerate(lines):
                    if re.match(r'\s*(?:django|flask|requests|numpy|tensorflow)\s*[<>=!]', line, re.IGNORECASE):
                        self.hits.append({"check": "S5", "risk": "R4", "points": 2, "file": fn,
                                        "content": f"依赖需CVE比对: {line.strip()}", "line": i+1,
                                        "flag": "cve_check_required"})
            
            # S6: 安装脚本行为
            if fn in ['setup.py', 'install.sh']:
                has_network = bool(re.search(r'requests|urllib|wget|curl.*http', full_text, re.IGNORECASE))
                has_exec = bool(re.search(r'os\.system|subprocess|exec\s*\n', full_text))
                if has_network and has_exec:
                    self.hits.append({"check": "S6", "risk": "R4", "points": 8, "file": fn,
                                    "content": "安装脚本含网络下载+执行链", "line": 0, "flag": "suspicious_install"})
            
            # S7: 文件权限修改
            for pat in [r'chmod', r'chown', r'icacls', r'Set-Acl']:
                for i, line in enumerate(lines):
                    if re.search(pat, line, re.IGNORECASE):
                        self.hits.append({"check": "S7", "risk": "R6", "points": 5, "file": fn,
                                        "content": line.strip(), "line": i+1, "flag": "permission_modify"})
            
            # S8: 注册表/配置篡改
            for pat in [r'reg\s+add', r'Set-ItemProperty', r'defaults\s+write']:
                for i, line in enumerate(lines):
                    if re.search(pat, line, re.IGNORECASE):
                        self.hits.append({"check": "S8", "risk": "R7", "points": 5, "file": fn,
                                        "content": line.strip(), "line": i+1, "flag": "registry_tamper"})
            
            # S9: 文件上传逻辑
            has_read = bool(re.search(r'read_file|open\s*\(', full_text))
            has_write = bool(re.search(r'write_file|write\s*\(|save', full_text))
            upload_keywords = bool(re.search(r'file_upload|multipart|upload', full_text, re.IGNORECASE))
            if (has_read and has_write) or upload_keywords:
                self.hits.append({"check": "S9", "risk": "R4", "points": 5, "file": fn,
                                "content": "含文件读写组合/上传逻辑", "line": 0, "flag": "unchecked_upload"})
            
            # S10: 外部 API 无校验
            has_http = bool(re.search(r'https?://', full_text))
            has_sig = bool(re.search(r'signature|verify|hmac|校验|签名', full_text, re.IGNORECASE))
            if has_http and not has_sig:
                self.hits.append({"check": "S10", "risk": "R5", "points": 3, "file": fn,
                                "content": "HTTP调用无签名验证机制", "line": 0, "flag": "unverified_api_call"})
            
            # S11: 数据收集静默
            for pat in [r'\.log\b', r'logging\.', r'collect\b', r'analytics', r'telemetry']:
                for i, line in enumerate(lines):
                    if re.search(pat, line, re.IGNORECASE):
                        self.hits.append({"check": "S11", "risk": "R9", "points": 3, "file": fn,
                                        "content": line.strip(), "line": i+1, "flag": "silent_data_collection"})
            
            # S12: 第三方 SDK 引入
            if fn.endswith(('.py', '.js')):
                imports = re.findall(r'(?:import|from|require)\s+(\S+)', full_text)
                for imp in imports:
                    if imp.startswith(('.', '..', '/', '~')):
                        continue
                    self.hits.append({"check": "S12", "risk": "R4", "points": 2, "file": fn,
                                    "content": f"第三方引入: {imp}", "line": 0, "flag": "unvetted_sdk"})
    
    def _check_permissions(self):
        """3.4 权限声明检查 P1-P11"""
        skill_md = "SKILL.md"
        lines = self.files.get(skill_md, [])
        full_text = "".join(lines)
        
        has_permission_section = bool(re.search(r'权限|permission', full_text, re.IGNORECASE))
        if not has_permission_section:
            self.hits.append({"check": "P1-P7", "risk": "R6", "points": 10, "file": skill_md,
                            "content": "无权限声明章节", "line": 0, "flag": "permissions_missing"})
            for check_id, flag in [("P8", "no_tenant_isolation"), ("P9", "no_resource_quota"),
                                     ("P10", "no_timeout_control"), ("P11", "no_chain_integrity")]:
                self.hits.append({"check": check_id, "risk": "R6", "points": 2, "file": skill_md,
                                "content": f"无{check_id}声明（无权限章节）", "line": 0, "flag": flag})
        else:
            if not re.search(r'隔离|isolation|tenant|租户|数据隔离', full_text):
                self.hits.append({"check": "P8", "risk": "R9", "points": 3, "file": skill_md,
                                "content": "无租户/用户数据隔离声明", "line": 0, "flag": "no_tenant_isolation"})
            if not re.search(r'CPU|内存|memory|配额|quota|频次|rate.?limit', full_text):
                self.hits.append({"check": "P9", "risk": "R6", "points": 2, "file": skill_md,
                                "content": "无资源配额声明", "line": 0, "flag": "no_resource_quota"})
            if not re.search(r'timeout|超时', full_text):
                self.hits.append({"check": "P10", "risk": "R6", "points": 2, "file": skill_md,
                                "content": "无超时控制声明", "line": 0, "flag": "no_timeout_control"})
            if not re.search(r'校验|verify|hash|signature|完整性|integrity', full_text):
                self.hits.append({"check": "P11", "risk": "R6", "points": 2, "file": skill_md,
                                "content": "无链路完整性校验声明", "line": 0, "flag": "no_chain_integrity"})
    
    def _check_data_security(self):
        """3.5 数据安全声明检查 D1-D7"""
        skill_md = "SKILL.md"
        lines = self.files.get(skill_md, [])
        full_text = "".join(lines)
        
        data_checks = [
            ("D1", r'PII|个人信息|personal.*(data|info)|收集.*数据|data.*collect', "无 PII 收集声明"),
            ("D2", r'脱敏|desensitize|mask|加密.*日志|log.*encrypt', "无敏感数据脱敏声明"),
            ("D3", r'TLS|SSL|AES|加密|encrypt', "无传输/存储加密声明"),
            ("D4", r'密钥.*管理|key.*(manage|rotate|vault)|token.*(manage|rotate)', "无密钥管理方式声明"),
            ("D5", r'删除.*数据|data.*delet|导出.*数据|data.*export|用户.*(删除|导出)', "无用户数据删除/导出声明"),
            ("D6", r'保留.*(天|月|年)|retention|auto.*destroy|自动.*销毁', "无数据保留期限声明"),
            ("D7", r'跨(境|域)|cross.?border|数据传输|data.*transfer', "无数据跨境传输合规声明"),
        ]
        
        for check_id, pattern, desc in data_checks:
            if not re.search(pattern, full_text, re.IGNORECASE):
                self.hits.append({"check": check_id, "risk": "R9", "points": 2, "file": skill_md,
                                "content": desc, "line": 0, "flag": f"data_{check_id.lower()}_missing"})
    
    def _gen_summary(self):
        """生成一句话审查总结"""
        n_issues = len(self.hits)
        n_veto = len(self.veto_items)
        n_redline = len(self.get_redline_hits())
        if n_veto > 0:
            self.summary = f"命中 {n_veto} 个一票否决项，{n_issues} 个常规问题"
        elif n_redline > 0:
            self.summary = f"命中 {n_redline} 条即时拒绝红线，{n_issues} 个常规问题"
        elif n_issues > 0:
            self.summary = f"发现 {n_issues} 个安全问题，无高危项"
        else:
            self.summary = "未发现安全问题，审查通过"
    
    def get_veto_hits(self) -> list:
        return self.veto_items
    
    def get_redline_hits(self) -> list:
        """检查所有文件中的 17 条即时拒绝红线"""
        redlines = [
            (r'curl.*(https?://|ftp://)', "向不明URL发起curl"),
            (r'wget.*(https?://|ftp://)', "向不明URL发起wget"),
            (r'(webhook|POST.*https?://|upload.*https?://)', "外发数据至外部服务器"),
            (r'(请输入.*密钥|读取.*凭证|read.*token|read.*api.?key|read.*password)', "索要凭证/Token"),
            (r'(~/.ssh|~/.aws|~/.config)', "读取凭证目录"),
            (r'(MEMORY\.md|USER\.md|SOUL\.md|IDENTITY\.md)', "读取Agent身份记忆文件"),
            (r'base64.*(decode|解码)', "Base64解码"),
            (r'eval\s*\(\s*(input|request|args|sys\.argv)', "eval接受外部输入"),
            (r'(/etc/|C:\\Windows\\|~/)(.*\.(conf|cfg|ini))', "修改系统配置文件"),
            (r'(pip\s+install|npm\s+install)\s+(?!-r)', "安装未声明依赖包"),
            (r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "网络调用使用IP直连"),
            (r'(eval\s*\(\s*base64|exec\s*\(\s*base64)', "混淆代码"),
            (r'(sudo\s|root|Administrator|提权)', "请求提权"),
            (r'(~/.aws/credentials|~/.kube/config|\.env\s|git-credentials)', "触碰凭证文件"),
            (r"(token\s*=\s*[\"\'][A-Za-z0-9+/=]{20,}|api_key\s*=\s*[\"\'][A-Za-z0-9+/=]{20,}|password\s*=\s*[\"\']\S)", "硬编码Token/API Key/密码"),
            (r'(email|phone|ID.?card|身份证|手机号).*\b(记录|存储|保存|log)', "日志记录明文PII"),
            (r'(hack|破解|crack|攻击).*(tutorial|教程|method|方法)', "生成有害内容指令"),
            (r'(完整输出|完整.*(复制|复述)|reproduce.*full|output.*entire).*(book|novel|chapter|小说|书)', "复述受版权保护全文"),
        ]
        
        redline_items = []
        for fn, lines in self.files.items():
            for i, line in enumerate(lines):
                for pat, desc in redlines:
                    if re.search(pat, line, re.IGNORECASE):
                        redline_items.append({"rule": desc, "content": line.strip()[:60],
                                             "file": fn, "line": i+1})
        return redline_items
    
    def get_deductions(self) -> list:
        return self.hits
    
    def get_stats(self) -> dict:
        files_scanned = len(self.files)
        checks_total = 52
        checks_hit = len(set(h['check'] for h in self.hits))
        checks_pass = checks_total - checks_hit
        return {
            "files_scanned": files_scanned,
            "checks_total": checks_total,
            "checks_hit": checks_hit,
            "checks_pass": checks_pass,
        }
