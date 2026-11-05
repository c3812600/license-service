"""前端契约测试：静态页与后端路由/设计 token 的一致性。

无浏览器环境下的结构化检查：
1. 页面里每个 fetch() 路径必须对应真实后端路由（防前端调幽灵接口）；
2. 设计 token 命名与 AGENTS.md 约定一致（三端共用一套）；
3. 深浅色切换与主题属性存在；
4. 页面能被 Flask 真实路由服务。

运行：python -m unittest tests.test_static_pages -v
"""

import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from license_service import create_app
from license_service.config import Config

ROOT = Path(__file__).resolve().parent.parent
PAGES = {
    "admin.html": ROOT / "license_service" / "static" / "admin.html",
    "stats.html": ROOT / "license_service" / "static" / "stats.html",
    "client-ui-demo.html": ROOT / "docs" / "client-ui-demo.html",
}
# AGENTS.md 约定的共享设计 token
DESIGN_TOKENS = (
    "--bg", "--card", "--border", "--text", "--text-dim",
    "--accent", "--accent-hover", "--success", "--warn", "--danger",
)


def _api_paths(html):
    """提取页面引用的所有 /api/v1/... 路径（覆盖 api()/fetch()/模板串/变量赋值），去掉查询串。"""
    return {match.rstrip("/") for match in re.findall(r"/api/v1/[A-Za-z0-9_/-]+", html)}


def _route_paths(app):
    return {rule.rule for rule in app.url_map.iter_rules()}


class StaticPageContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        cls.config_patch = patch.multiple(
            Config,
            ADMIN_TOKEN="test-admin",
            MACHINE_CODE_SALT="test-salt",
            DATABASE_PATH=str(root / "db.sqlite"),
            PRIVATE_KEY_PATH=str(root / "private.pem"),
            PUBLIC_KEY_PATH=str(root / "public.pem"),
            RATE_LIMIT_ENABLED=False,
        )
        cls.config_patch.start()
        cls.app = create_app()
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.config_patch.stop()
        cls.temp.cleanup()

    def test_every_api_path_is_a_real_route(self):
        """页面引用的每个 /api/ 路径都必须在后端 url_map 里（防幽灵接口）。

        client-ui-demo.html 是纯离线状态演示（不发真实请求），单独断言其无 /api/ 引用。
        """
        routes = _route_paths(self.app)
        for name in ("admin.html", "stats.html"):
            html = PAGES[name].read_text(encoding="utf-8")
            referenced = _api_paths(html)
            self.assertTrue(referenced, f"{name}: 未提取到 /api/ 路径，提取规则可能失效")
            missing = sorted(p for p in referenced if p not in routes)
            self.assertEqual(
                missing, [],
                f"{name}: 以下接口路径没有对应后端路由：{missing}",
            )
        demo_html = PAGES["client-ui-demo.html"].read_text(encoding="utf-8")
        self.assertEqual(
            _api_paths(demo_html), set(),
            "client-ui-demo.html 应为纯离线演示，不应引用真实接口",
        )

    def test_design_tokens_shared_across_pages(self):
        """三端页面定义同一套设计 token（AGENTS.md 前端约定）。"""
        for name, path in PAGES.items():
            html = path.read_text(encoding="utf-8")
            absent = [token for token in DESIGN_TOKENS if f"{token}:" not in html]
            self.assertEqual(absent, [], f"{name}: 缺少设计 token {absent}")

    def test_theme_toggle_present(self):
        """admin/stats 支持 data-theme 深浅色切换。"""
        for name in ("admin.html", "stats.html"):
            html = PAGES[name].read_text(encoding="utf-8")
            self.assertIn("data-theme", html, f"{name}: 缺少 data-theme 主题切换")

    def test_pages_served_by_flask(self):
        """静态页真实可达（路由挂载没断）。"""
        for url in ("/admin", "/admin/stats"):
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200, url)
            self.assertGreater(len(response.data), 1000, url)

    def test_error_envelope_fields_consumed_consistently(self):
        """联网页面读取的是 data/error 字段，与后端信封一致。"""
        for name in ("admin.html", "stats.html"):
            html = PAGES[name].read_text(encoding="utf-8")
            self.assertIn(".data", html, f"{name}: 未读取 data 字段")
            self.assertIn("error", html, f"{name}: 未处理 error 字段")


if __name__ == "__main__":
    unittest.main()
