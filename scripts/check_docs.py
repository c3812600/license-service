#!/usr/bin/env python3
"""校验 Markdown 内部链接：相对路径目标必须存在。

正文里引用别的文档/图片是最容易在改名、挪目录后失效的东西（本仓库刚把
规范文档从根目录挪到 docs/），CI 里跑一遍可以避免"文档指向 404"。

用法：python scripts/check_docs.py [仓库根目录]
"""

import pathlib
import re
import sys

LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
SKIP_PREFIXES = ("http://", "https://", "mailto:", "#", "tel:")


def strip_code_blocks(text):
    """去掉 ``` 围栏代码块，避免把示例里的假链接当成真链接。"""
    return re.sub(r"```.*?```", "", text, flags=re.DOTALL)


def broken_links(root):
    broken = []
    for md in sorted(root.rglob("*.md")):
        if ".git" in md.parts or "node_modules" in md.parts:
            continue
        text = strip_code_blocks(md.read_text(encoding="utf-8"))
        for raw in LINK_RE.findall(text):
            target = raw.strip()
            if target.startswith(SKIP_PREFIXES):
                continue
            path_part = target.split("#", 1)[0].strip()
            if not path_part:
                continue
            # 兼容 URL 编码的中文/空格路径
            path_part = path_part.replace("%20", " ")
            resolved = (md.parent / path_part).resolve()
            if not resolved.exists():
                broken.append(f"{md.relative_to(root)}: {target}")
    return broken


def main(argv):
    root = pathlib.Path(argv[1] if len(argv) > 1 else ".").resolve()
    broken = broken_links(root)
    if broken:
        print("发现失效的文档内部链接：")
        print("\n".join(f"  - {item}" for item in broken))
        return 1
    print(f"文档内部链接检查通过：{root}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
