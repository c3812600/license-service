"""文档↔代码契约测试：防止文档与实现漂移。

只守护**持久不变量**（路由、错误码、环境变量、表结构、过时标记、敏感物）；
一次性审计不在此列。改接口/错误码/配置时若这里红了，说明文档没跟上——
AGENTS.md 硬约束：「文档是唯一事实源」。

运行：python -m unittest tests.test_doc_contract -v
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
SPEC = (ROOT / "docs" / "license-design-spec.md").read_text(encoding="utf-8")
AGENTS = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
ENV_EXAMPLE = (ROOT / ".env.example").read_text(encoding="utf-8")

PY_DIR = ROOT / "license_service"
ROUTES_SRC = (PY_DIR / "__init__.py").read_text(encoding="utf-8")
CONFIG_SRC = (PY_DIR / "config.py").read_text(encoding="utf-8")
DB_SRC = (PY_DIR / "db.py").read_text(encoding="utf-8")

ALL_PY = "\n".join(
    (PY_DIR / name).read_text(encoding="utf-8")
    for name in ("__init__.py", "service.py", "device_auth.py", "crypto.py", "errors.py", "config.py", "db.py")
)


def _api_routes():
    return sorted({
        (m.group(1).upper(), m.group(2))
        for m in re.finditer(r'@app\.(get|post|patch)\("([^"]+)"\)', ROUTES_SRC)
        if m.group(2).startswith("/api/")
    })


class DocContractTests(unittest.TestCase):
    def test_every_api_route_documented(self):
        """代码里的每条 API 路由都要出现在 README 接口表与规范全文。"""
        for method, path in _api_routes():
            with self.subTest(route=f"{method} {path}"):
                self.assertIn(f"`{path}`", README, f"README 接口表缺 {method} {path}")
                short = path.removeprefix("/api/v1").lstrip("/")
                self.assertTrue(
                    f"`{path}`" in SPEC or f"`{short}`" in SPEC or path in SPEC,
                    f"规范缺 {method} {path}",
                )

    def test_every_error_code_documented(self):
        """代码在用的业务错误码必须出现在规范 §8.4；§8.4 的码要么在用要么是保留码。"""
        codes_used = set(re.findall(
            r'(?:InputError|ForbiddenError|ConflictError|NotFoundError)\("[^"]*",\s*"([A-Z_]+)"\)',
            ALL_PY,
        ))
        codes_used |= set(re.findall(r'\d+: "([A-Z_]+)"', ROUTES_SRC))  # _ERROR_CODES_BY_STATUS
        sec84 = SPEC[SPEC.find("### 4. 错误码"):SPEC.find("### 5. 持证换钥")]
        for code in sorted(codes_used):
            with self.subTest(code=code):
                self.assertIn(f"`{code}`", sec84, f"代码在用的 {code} 未写进规范 §8.4")
        reserved = {"NOT_BEFORE", "TIME_ROLLBACK", "SERVICE_UNAVAILABLE"}
        declared = set(re.findall(r"`([A-Z][A-Z_]{2,})`", sec84))
        for code in sorted(declared - codes_used - reserved):
            with self.subTest(declared=code):
                self.fail(f"规范 §8.4 声明了 {code}，但代码既未使用也非保留码")

    def test_every_env_var_documented(self):
        """config.py 读取的环境变量都要在 .env.example 里有条目。"""
        env_read = set(re.findall(r'os\.environ\.get\("([A-Z_]+)"', CONFIG_SRC))
        env_read |= set(re.findall(r'_env_prefixed\("([A-Z_]+)"', CONFIG_SRC))
        for var in sorted(env_read):
            with self.subTest(var=var):
                self.assertIn(var, ENV_EXAMPLE, f"{var} 未写进 .env.example")

    def test_schema_version_matches_spec(self):
        """db.SCHEMA_VERSION 与规范附录 I 的「当前 N」一致。"""
        code_ver = re.search(r"SCHEMA_VERSION = (\d+)", DB_SRC).group(1)
        spec_ver = re.search(r"与 `db.SCHEMA_VERSION` 对应；当前 `(\d+)`", SPEC)
        self.assertIsNotNone(spec_ver, "规范附录 I 缺少「当前 N」表述")
        self.assertEqual(code_ver, spec_ver.group(1), "SCHEMA_VERSION 与规范不一致")

    def test_every_table_documented(self):
        """init_db 建的每张表都要出现在规范附录 I。"""
        tables = set(re.findall(r"CREATE TABLE IF NOT EXISTS ([a-z_]+)", DB_SRC))
        appendix_i = SPEC[SPEC.find("### 1. 表结构"):]
        for table in sorted(tables):
            with self.subTest(table=table):
                self.assertIn(f"`{table}`", appendix_i, f"表 {table} 未写进规范附录 I")

    def test_no_stale_deployment_markers(self):
        """上线后不得残留「待部署/尚未部署」等过时状态标记。"""
        stale = [
            (r"尚未部署", "「尚未部署」"),
            (r"待部署", "「待部署」"),
            (r"当前不返回业务", "「不返回 code」"),
            (r"接口待定稿", "「接口待定稿」"),
        ]
        for doc_name, text in (("README", README), ("规范", SPEC), ("AGENTS", AGENTS)):
            for pattern, label in stale:
                with self.subTest(doc=doc_name, marker=label):
                    self.assertIsNone(re.search(pattern, text), f"{doc_name} 残留{label}")

    def test_no_secrets_in_docs(self):
        """文档不得出现真实私钥/令牌/盐。"""
        for doc_name, text in (("README", README), ("规范", SPEC), ("AGENTS", AGENTS)):
            with self.subTest(doc=doc_name):
                self.assertNotRegex(text, r"(?:ADMIN_TOKEN|MACHINE_CODE_SALT)=[A-Za-z0-9]{8,}")
                self.assertNotRegex(text, r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


if __name__ == "__main__":
    unittest.main()
