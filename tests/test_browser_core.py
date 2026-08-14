import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path


# 测试环境可能没有安装 Tk；扫描内核在导入阶段不依赖图形能力，因此提供最小桩。
try:
    import tkinter  # noqa: F401
except ModuleNotFoundError:
    tkinter_stub = types.ModuleType("tkinter")
    tkinter_stub.Tk = object
    tkinter_stub.filedialog = types.SimpleNamespace()
    tkinter_stub.messagebox = types.SimpleNamespace()
    tkinter_stub.ttk = types.SimpleNamespace()
    sys.modules["tkinter"] = tkinter_stub

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
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("CREATE TABLE urls (url TEXT)")
        writer.execute("INSERT INTO urls(url) VALUES (?)", ("https://wal-hit.example.test/record",))
        writer.commit()

        self.assertTrue((self.root / "History-wal").exists())
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

        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0]["b"], "Chrome Dev")
        self.assertEqual(profiles[0]["p"], "Default")

    def test_manual_profile_path_is_recognised(self):
        profile = self.root / "Custom Profile"
        profile.mkdir()
        (profile / "History").write_bytes(b"SQLite format 3\\x00")
        ScannerCore._reset_diagnostics()
        profiles = ScannerCore._collect_explicit_paths([profile], set())
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0]["path"], str(profile))
        self.assertEqual(profiles[0]["source"], "手动选择路径")

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
