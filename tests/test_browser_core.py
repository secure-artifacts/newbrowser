import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock


# 扫描内核测试不依赖图形能力。云构建可强制使用最小 Tk 桩，避免宿主 Python 的
# Tcl/Tk 安装差异干扰数据库与路径发现回归测试。
def install_tk_stub() -> None:
    tkinter_stub = types.ModuleType("tkinter")
    tkinter_stub.Tk = object
    tkinter_stub.filedialog = types.SimpleNamespace()
    tkinter_stub.messagebox = types.SimpleNamespace()
    tkinter_stub.ttk = types.SimpleNamespace()
    sys.modules["tkinter"] = tkinter_stub


if os.environ.get("BROWSER_AUDIT_HEADLESS_TESTS") == "1":
    sys.modules.pop("tkinter", None)
    install_tk_stub()
else:
    try:
        import tkinter  # noqa: F401
    except ModuleNotFoundError:
        install_tk_stub()

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILE = PROJECT_ROOT / "browser_Gui.py"
SPEC = importlib.util.spec_from_file_location("browser_gui_under_test", SOURCE_FILE)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)
ScannerCore = MODULE.ScannerCore


class ScannerCoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_online_backup_reads_committed_wal_content(self):
        database = self.root / "History"
        writer = sqlite3.connect(database)
        journal_mode = writer.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        self.assertEqual(str(journal_mode).lower(), "wal")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("CREATE TABLE urls (url TEXT)")
        writer.execute("INSERT INTO urls(url) VALUES (?)", ("https://wal-hit.example.test/record",))
        writer.commit()

        # Windows 的 SQLite/VFS 可能延迟创建或清理 -wal 侧车文件；以已启用的
        # WAL 模式和在线快照的已提交内容作为跨平台行为断言，而非文件时序。
        snapshot = ScannerCore._snapshot_database(database, self.root)
        self.assertIsNotNone(snapshot)
        try:
            snapshot_connection = sqlite3.connect(snapshot)
            values = snapshot_connection.execute("SELECT url FROM urls").fetchall()
            snapshot_connection.close()
            self.assertEqual(values, [("https://wal-hit.example.test/record",)])
        finally:
            if snapshot is not None:
                snapshot.unlink(missing_ok=True)
            writer.close()

    def test_collect_chromium_profiles_uses_local_state_name(self):
        user_data = self.root / "Google" / "Chrome" / "User Data"
        profile = user_data / "Profile 2"
        profile.mkdir(parents=True)
        (profile / "History").write_bytes(b"SQLite format 3\x00")
        (user_data / "Local State").write_text(
            json.dumps({"profile": {"info_cache": {"Profile 2": {"name": "工作账号"}}}}),
            encoding="utf-8",
        )

        profiles = ScannerCore._collect_chrome_profiles(user_data, "Chrome", set(), "测试")
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0]["p"], "Profile 2（工作账号）")
        self.assertEqual(profiles[0]["source"], "测试")

    def test_bookmarks_only_profile_is_discovered_and_scanned_without_history(self):
        user_data = self.root / "Google" / "Chrome" / "User Data"
        profile_dir = user_data / "Profile 463"
        profile_dir.mkdir(parents=True)
        (profile_dir / "Bookmarks").write_text(
            json.dumps(
                {
                    "roots": {
                        "bookmark_bar": {
                            "type": "folder",
                            "children": [
                                {"type": "url", "url": "https://mailum.com/bookmark"}
                            ],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        profiles = ScannerCore._collect_chrome_profiles(user_data, "Chrome", set(), "测试")
        self.assertEqual(len(profiles), 1)
        hits = ScannerCore.scan(profiles[0], {"mailum.com": "命中"}, self.root)
        self.assertEqual([hit[4] for hit in hits], ["https://mailum.com/bookmark"])
        self.assertTrue(ScannerCore.scan_is_complete())

    def test_invalid_history_does_not_block_bookmarks(self):
        profile_dir = self.root / "Default"
        profile_dir.mkdir()
        (profile_dir / "History").write_bytes(b"not-a-sqlite-file")
        (profile_dir / "Bookmarks").write_text(
            json.dumps({"roots": {"other": {"url": "https://bookmark-only.example.test/"}}}),
            encoding="utf-8",
        )
        ScannerCore._reset_diagnostics()
        profile = {"b": "Chrome", "p": "Default", "path": str(profile_dir), "type": "C", "source": "测试"}
        hits = ScannerCore.scan(profile, {"bookmark-only.example.test": "命中"}, self.root)
        self.assertEqual([hit[4] for hit in hits], ["https://bookmark-only.example.test/"])
        self.assertFalse(ScannerCore.scan_is_complete())

    def test_repeat_scan_after_history_removal_still_finds_bookmark(self):
        profile_dir = self.root / "Default"
        profile_dir.mkdir()
        database = sqlite3.connect(profile_dir / "History")
        database.execute("CREATE TABLE urls (url TEXT)")
        database.commit()
        database.close()
        (profile_dir / "Bookmarks").write_text(
            json.dumps({"roots": {"other": {"url": "https://repeat.example.test/saved"}}}),
            encoding="utf-8",
        )
        profile = {"b": "Chrome", "p": "Default", "path": str(profile_dir), "type": "C", "source": "测试"}
        rules = {"repeat.example.test": "命中"}
        first = ScannerCore.scan(profile, rules, self.root)
        (profile_dir / "History").unlink()
        ScannerCore._reset_diagnostics()
        second = ScannerCore.scan(profile, rules, self.root)
        self.assertEqual([hit[4] for hit in first], ["https://repeat.example.test/saved"])
        self.assertEqual([hit[4] for hit in second], ["https://repeat.example.test/saved"])
        self.assertTrue(ScannerCore.scan_is_complete())

    def test_local_state_indexed_profile_is_discovered_before_history_initialisation(self):
        user_data = self.root / "User Data"
        profile_dir = user_data / "Profile 88"
        profile_dir.mkdir(parents=True)
        (user_data / "Local State").write_text(
            json.dumps({"profile": {"info_cache": {"Profile 88": {"name": "尚未启动"}}}}),
            encoding="utf-8",
        )
        profiles = ScannerCore._collect_chrome_profiles(user_data, "Chrome", set(), "测试")
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0]["p"], "Profile 88（尚未启动）")

    def test_chromium_download_variants_are_all_scanned(self):
        profile_dir = self.root / "Default"
        profile_dir.mkdir()
        database = profile_dir / "History"
        connection = sqlite3.connect(database)
        connection.execute("CREATE TABLE urls (url TEXT)")
        connection.execute("INSERT INTO urls(url) VALUES (?)", ("https://history.example.test/a",))
        connection.execute("CREATE TABLE downloads (target_path TEXT, tab_url TEXT, site_url TEXT)")
        connection.execute(
            "INSERT INTO downloads(target_path, tab_url, site_url) VALUES (?, ?, ?)",
            ("C:/safe.txt", "https://download.example.test/b", "https://site.example.test/c"),
        )
        connection.execute("CREATE TABLE downloads_url_chains (url TEXT)")
        connection.execute("INSERT INTO downloads_url_chains(url) VALUES (?)", ("https://chain.example.test/d",))
        connection.commit()
        connection.close()

        profile = {"b": "Chrome", "p": "Default", "path": str(profile_dir), "type": "C", "source": "测试"}
        rules = {
            "history.example.test": "命中",
            "download.example.test": "命中",
            "site.example.test": "命中",
            "chain.example.test": "命中",
        }
        hits = ScannerCore.scan(profile, rules, self.root)
        urls = {hit[4] for hit in hits}
        self.assertTrue({
            "https://history.example.test/a",
            "https://download.example.test/b",
            "https://site.example.test/c",
            "https://chain.example.test/d",
        }.issubset(urls))

    def test_windows_discovery_uses_localappdata_not_login_name(self):
        local_app_data = self.root / "redirected" / "Local"
        profile = local_app_data / "Google" / "Chrome Dev" / "User Data" / "Default"
        profile.mkdir(parents=True)
        (profile / "History").write_bytes(b"SQLite format 3\\x00")

        old_platform = MODULE.sys.platform
        old_local_app_data = os.environ.get("LOCALAPPDATA")
        try:
            MODULE.sys.platform = "win32"
            os.environ["LOCALAPPDATA"] = str(local_app_data)
            profiles = ScannerCore.get_profiles()
        finally:
            MODULE.sys.platform = old_platform
            if old_local_app_data is None:
                os.environ.pop("LOCALAPPDATA", None)
            else:
                os.environ["LOCALAPPDATA"] = old_local_app_data

        # Windows 托管运行器可能预装 Edge/Chrome 资料；测试只验证重定向的
        # LOCALAPPDATA 中目标 Profile 被发现，不能假设全机只有一个配置。
        expected_path = str(profile)
        matching_profiles = [item for item in profiles if item["path"] == expected_path]
        self.assertEqual(len(matching_profiles), 1)
        self.assertEqual(matching_profiles[0]["b"], "Chrome Dev")
        self.assertEqual(matching_profiles[0]["p"], "Default")

    def test_manual_profile_path_is_recognised(self):
        profile = self.root / "Custom Profile"
        profile.mkdir()
        (profile / "History").write_bytes(b"SQLite format 3\\x00")
        ScannerCore._reset_diagnostics()
        profiles = ScannerCore._collect_explicit_paths([profile], set())
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0]["path"], str(profile))
        self.assertEqual(profiles[0]["source"], "手动选择路径")

    def test_manual_google_parent_directory_is_recognised(self):
        google_dir = self.root / "Google"
        profile = google_dir / "Chrome" / "User Data" / "Default"
        profile.mkdir(parents=True)
        (profile / "History").write_bytes(b"SQLite format 3\\x00")

        ScannerCore._reset_diagnostics()
        profiles = ScannerCore._collect_explicit_paths([google_dir], set())
        self.assertEqual(len(profiles), 1)
        self.assertIn("Chrome", profiles[0]["b"])
        self.assertEqual(profiles[0]["source"], "手动选择路径")
        self.assertNotIn("目录不是可识别", ScannerCore.diagnostics_text())

    def test_invalid_database_is_isolated_from_following_profile(self):
        invalid_profile = self.root / "Invalid"
        invalid_profile.mkdir()
        (invalid_profile / "History").write_bytes(b"not-a-sqlite-file")
        valid_profile = self.root / "Valid"
        valid_profile.mkdir()
        database = sqlite3.connect(valid_profile / "History")
        database.execute("CREATE TABLE urls (url TEXT)")
        database.execute("INSERT INTO urls(url) VALUES (?)", ("https://isolated.example.test/ok",))
        database.commit()
        database.close()

        ScannerCore._reset_diagnostics()
        bad = {"b": "Chrome", "p": "Invalid", "path": str(invalid_profile), "type": "C", "source": "测试"}
        good = {"b": "Chrome", "p": "Valid", "path": str(valid_profile), "type": "C", "source": "测试"}
        self.assertEqual(ScannerCore.scan(bad, {"isolated.example.test": "命中"}, self.root), [])
        good_hits = ScannerCore.scan(good, {"isolated.example.test": "命中"}, self.root)
        self.assertEqual(len(good_hits), 1)
        self.assertIn("一致性快照失败", ScannerCore.diagnostics_text())

    def test_diagnostics_redacts_profile_display_name(self):
        profile_dir = self.root / "Invalid"
        profile_dir.mkdir()
        (profile_dir / "History").write_bytes(b"not-a-sqlite-file")
        ScannerCore._reset_diagnostics()
        profile = {
            "b": "Chrome",
            "p": "Default（confidential.user@example.com）",
            "path": str(profile_dir),
            "type": "C",
            "source": "测试",
        }
        ScannerCore.scan(profile, {}, self.root)
        diagnostic = ScannerCore.diagnostics_text()
        self.assertIn("Chrome / Default", diagnostic)
        self.assertNotIn("confidential.user@example.com", diagnostic)

    def test_expired_snapshot_budget_skips_profile_quickly(self):
        database = sqlite3.connect(self.root / "History")
        database.execute("CREATE TABLE urls (url TEXT)")
        database.commit()
        database.close()

        ScannerCore._reset_diagnostics()
        started = time.monotonic()
        snapshot = ScannerCore._snapshot_database(self.root / "History", self.root, time.monotonic() - 0.01)
        self.assertIsNone(snapshot)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertIn("一致性快照超时", ScannerCore.diagnostics_text())

    def test_url_row_limit_records_diagnostic_without_hanging(self):
        database = sqlite3.connect(self.root / "limit.sqlite")
        database.execute("CREATE TABLE urls (url TEXT)")
        database.executemany("INSERT INTO urls(url) VALUES (?)", [(f"https://row{i}.example.test/",) for i in range(5)])
        database.commit()
        cursor = database.cursor()
        original_limit = MODULE.MAX_URL_ROWS_PER_TABLE
        try:
            MODULE.MAX_URL_ROWS_PER_TABLE = 2
            ScannerCore._reset_diagnostics()
            hits = []
            ScannerCore._read_urls(
                cursor,
                "SELECT url FROM urls",
                {"b": "Chrome", "p": "Default"},
                "历史记录",
                {"example.test": "命中"},
                hits,
                time.monotonic() + 1.0,
            )
        finally:
            MODULE.MAX_URL_ROWS_PER_TABLE = original_limit
            database.close()
        self.assertEqual(len(hits), 2)
        self.assertIn("读取限额", ScannerCore.diagnostics_text())
        self.assertFalse(ScannerCore.scan_is_complete())

    def test_rule_parser_keeps_specific_label_and_supports_tld_rule(self):
        rule_file = self.root / "custom-domains.conf"
        rule_file.write_text(
            "hailuoai.com=AI服务(海螺AI)\n"
            "server=/hailuoai.com/114.114.114.114\n"
            "server=/cn/114.114.114.114\n",
            encoding="utf-8",
        )
        with mock.patch.object(MODULE.ResourceManager, "_candidate_rule_files", return_value=[rule_file]):
            rules = MODULE.ResourceManager.load_audit_rules()
        self.assertEqual(rules["hailuoai.com"], "AI服务(海螺AI)")
        self.assertEqual(rules["cn"], "专项审计目标")
        hits = []
        ScannerCore._match(
            "https://example.cn/path",
            "浏览器书签",
            {"b": "Chrome", "p": "Default"},
            rules,
            hits,
        )
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][3], "专项审计目标")

    def test_release_rule_file_loads_large_ruleset(self):
        rule_file = PROJECT_ROOT / "custom-domains.conf"
        with mock.patch.object(MODULE.ResourceManager, "_candidate_rule_files", return_value=[rule_file]):
            rules = MODULE.ResourceManager.load_audit_rules()
        self.assertGreater(len(rules), 100_000)
        self.assertEqual(rules["hailuoai.com"], "AI服务(海螺AI)")
        self.assertEqual(rules["cn"], "专项审计目标")

    def test_release_version_is_1_1_9(self):
        self.assertEqual(MODULE.APP_VERSION, "1.1.9")

    def test_chromium_candidate_layouts_cover_non_stable_channels(self):
        candidates = ScannerCore._chromium_candidate_dirs(self.root)
        names = {name for name, _ in candidates}
        self.assertTrue({"Chrome", "Chrome Beta", "Chrome Dev", "Chrome Canary", "Chrome for Testing", "Chromium"}.issubset(names))

    def test_match_uses_hostname_and_respects_whitelist(self):
        hits = []
        profile = {"b": "Chrome", "p": "Default"}
        ScannerCore._match("https://sub.example.test:8443/path", "历史记录", profile, {"example.test": "命中"}, hits)
        ScannerCore._match("https://sub.google.com/path", "历史记录", profile, {"google.com": "不应命中"}, hits)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][4], "https://sub.example.test:8443/path")


if __name__ == "__main__":
    unittest.main(verbosity=2)
