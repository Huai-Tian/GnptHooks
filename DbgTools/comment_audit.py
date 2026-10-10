#!/usr/bin/env python3
# GnptHooks 注释规范审计(commit门禁用)
# 铁律12: 注释只留功能叙述/契约/硬件语义(APM章节号)/跨文件同步提示;
# 禁止里程碑号/版本历史/判例引用/修复史/姊妹项目名/过程叙事。
#
# 用法: python comment_audit.py [src目录]   (默认: 脚本上级的src/)
# 退出码: 0=干净 1=有违规(打印逐条定位)
# 白名单: 字符串字面量与日志文案(FlLog/FlRingPush/DbgPrint参数)不属注释;
#         变体开关自身的功能枚举(0=全功能 1=全停...)允许出现数字。
import re, sys, os

# 禁词模式(注释行命中即违规; 白名单条目需人工确认语境)
PATTERNS = [
    (r'v0\.[0-9]{1,2}[a-z]*', '版本号'),
    (r'(?<![0-9A-Za-z.])M\d{1,2}\.\d{1,2}(?![0-9])', '里程碑号'),
    (r'判例', '判例引用'),
    (r'NOTES|HANDOFF', '内部文档交叉引用'),
    (r'GeptHooks|Gept', '姊妹项目名'),
    (r'定罪|裁决|翻案|悬案', '过程叙事'),
    (r'实测[:：]|轮实测|实测死|单变量翻转', '实测叙事'),
]
# 白名单: 完整行允许的语境(热探测等运行时测量是功能不是历史)
LINE_ALLOW = re.compile(
    r'必须实测|实测窗口|实测筛选|页冷实测|热探针实测|实测说了算')

def strip_strings(code):
    # 去字符串字面量(注释审计不看日志文案)
    code = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', code)
    code = re.sub(r"'(?:\\.|[^'\\\n])*'", "''", code)
    return code

def audit(path):
    bad = []
    code = strip_strings(open(path, encoding='utf-8', errors='replace').read())
    for no, line in enumerate(code.splitlines(), 1):
        # 只看注释部分: 行注释与块注释残余(块注释整体剥离)
        pass
    # 更精确: 提取 // 注释与 /* */ 块
    text = re.sub(r'/\*.*?\*/', lambda m: '\n'*m.group(0).count('\n'), code, flags=re.S)
    for no, line in enumerate(text.splitlines(), 1):
        idx = line.find('//')
        if idx < 0:
            continue
        seg = line[idx:]
        if LINE_ALLOW.search(seg):
            continue
        for pat, why in PATTERNS:
            for m in re.finditer(pat, seg):
                bad.append((path, no, why, m.group(0), seg.strip()[:80]))
    return bad

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), os.pardir, 'src')
    bad = []
    for f in sorted(os.listdir(root)):
        if f.endswith(('.c', '.h')):
            bad += audit(os.path.join(root, f))
    if not bad:
        print('comment_audit: 干净(0违规)')
        return 0
    print('comment_audit: %d 处违规' % len(bad))
    for path, no, why, tok, seg in bad:
        print('  %s:%d [%s] %s | %s' % (os.path.basename(path), no, why, tok, seg))
    return 1

if __name__ == '__main__':
    sys.exit(main())
