import html
import json
import logging
import os
import plistlib
import queue
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import tkinter as tk
from tkinter import filedialog, messagebox, ttk


# =================================================
# 0. 全局配置
# =================================================
APP_VERSION = "1.1.8"
MAX_RULE_FILE_BYTES = 10 * 1024 * 1024
MAX_RULE_COUNT = 250_000
MAX_MATCHES = 100_000
# 单个异常 Profile 不能无限占用扫描线程；限制会写入无敏感诊断信息。
PROFILE_SCAN_BUDGET_SECONDS = 12.0
SESSION_SCAN_BUDGET_SECONDS = 180.0
SNAPSHOT_BUDGET_SECONDS = 4.0
MAX_URL_ROWS_PER_TABLE = 100_000

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

DEFAULT_INTERNAL_RULES = {
    "heygen.com": "AI视频(HeyGen)",
    "hailuoai.com": "AI服务(海螺AI)",
    "mailum.com": "未知安全邮箱",
    "tongyi.aliyun.com": "AI服务(阿里通义)",
    "doubao.com": "AI服务(字节豆包)",
    "yuanbao.tencent.com": "AI服务(腾讯元宝)",
    "yiyan.baidu.com": "AI服务(文心一言)",
    "tiangong.cn": "AI服务(昆仑天工)",
    "kimi.ai": "AI服务(月暗Kimi)",
    "deepseek.com": "AI服务(DeepSeek)",
    "chatglm.cn": "AI服务(智谱清言)",
    "baichuan-ai.com": "AI服务(百川智能)",
    "minimax.chat": "AI服务(MiniMax星野)",
    "klingai.com": "AI视频(快手可灵)",
    "viggle.ai": "AI视频(Viggle动画)",
    "shengxiang.baidu.com": "AI视频(百度生息)",
    "dreamina.capcut.com": "专项审计目标",
}


def get_base_directory() -> Path:
    """获取可执行程序旁的资源目录，并兼容 macOS App Translocation。"""
    if getattr(sys, "frozen", False):
        if sys.platform == "darwin":
            exec_dir = Path(sys.executable).parent
            if exec_dir.name == "MacOS" and exec_dir.parent.name == "Contents":
                app_path = exec_dir.parent.parent
                parent_dir = app_path.parent
                if "AppTranslocation" in str(parent_dir) or "/var/folders" in str(parent_dir):
                    return Path(tempfile.gettempdir())
                return parent_dir
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent


BASE_DIR = get_base_directory()


# =================================================
# 1. 规则资源管理
# =================================================
class ResourceManager:
    @staticmethod
    def initialize() -> None:
        """保留初始化入口，避免未来版本破坏调用方兼容性。"""

    @staticmethod
    def is_browser_running() -> List[str]:
        browsers = ["chrome", "msedge", "brave", "360se", "360chrome", "firefox", "safari"]
        running: List[str] = []
        try:
            if sys.platform == "win32":
                tasks = subprocess.check_output(
                    ["tasklist", "/fo", "csv", "/nh"], text=True, errors="ignore"
                ).lower()
                for browser in browsers:
                    if f'"{browser}.exe"' in tasks:
                        running.append(browser)
            else:
                tasks = subprocess.check_output(
                    ["ps", "-e", "-o", "comm="], text=True, errors="ignore"
                ).splitlines()
                for task in tasks:
                    process_name = Path(task.strip()).name.lower()
                    for browser in browsers:
                        if browser not in running and (
                            process_name == browser or process_name.startswith(f"{browser}.")
                        ):
                            running.append(browser)
        except (OSError, subprocess.SubprocessError) as exc:
            logger.debug("浏览器进程检测失败：%s", exc)
        return running

    @staticmethod
    def _candidate_rule_files() -> List[Path]:
        candidates: List[Path] = []
        if getattr(sys, "frozen", False):
            if sys.platform == "darwin":
                exec_dir = Path(sys.executable).parent
                if exec_dir.name == "MacOS" and exec_dir.parent.name == "Contents":
                    candidates.append(exec_dir.parent.parent.parent / "custom-domains.conf")
            candidates.append(Path(sys.executable).parent / "custom-domains.conf")
        else:
            candidates.append(Path(__file__).resolve().parent / "custom-domains.conf")

        # 允许管理员通过当前用户的文档目录维护额外规则；外部文件仅作为数据读取，不执行。
        docs_dir = Path.home() / "Documents" / "浏览器痕迹分析配置"
        docs_conf = docs_dir / "custom-domains.conf"
        candidates.append(docs_conf)
        if not docs_conf.exists():
            try:
                docs_dir.mkdir(parents=True, exist_ok=True)
                docs_conf.write_text(
                    "# 专项规则库（自定义扩展区）\n"
                    "# 格式：example.com=自定义分类\n",
                    encoding="utf-8",
                )
            except OSError as exc:
                logger.debug("无法创建用户规则文件：%s", exc)
        return candidates

    @staticmethod
    def load_audit_rules() -> Dict[str, str]:
        rules: Dict[str, str] = {}
        server_pattern = re.compile(r"^server=/([^/]+)/")

        for rule_file in ResourceManager._candidate_rule_files():
            if not rule_file.exists() or not rule_file.is_file():
                continue
            try:
                if rule_file.stat().st_size > MAX_RULE_FILE_BYTES:
                    logger.warning("规则文件过大，已忽略：%s", rule_file.name)
                    continue
                with rule_file.open("r", encoding="utf-8", errors="ignore") as file_handler:
                    for line in file_handler:
                        if len(rules) >= MAX_RULE_COUNT:
                            logger.warning("规则数量达到上限 %d，停止读取", MAX_RULE_COUNT)
                            break
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.startswith("server="):
                            match = server_pattern.match(line)
                            if match:
                                domain = match.group(1).strip().lower()
                                if len(domain) >= 4 and "." in domain:
                                    rules[domain] = "专项审计目标"
                        elif "=" in line:
                            domain, label = line.split("=", 1)
                            domain = domain.strip().lower()
                            if len(domain) >= 4 and "." in domain:
                                rules[domain] = label.strip()[:120] or "自定义分类"
            except (OSError, UnicodeError) as exc:
                logger.warning("解析规则文件失败 [%s]：%s", rule_file.name, exc)

        for domain, label in DEFAULT_INTERNAL_RULES.items():
            rules.setdefault(domain, label)
        return rules


# =================================================
# 2. 扫描内核
# =================================================
class ScanBudgetExceeded(RuntimeError):
    """单个 Profile 的可控扫描时间预算已耗尽。"""


class ScannerCore:
    """浏览器资料发现和只读扫描内核。

    设计原则：先使用当前进程的实际环境变量定位资料；扩展扫描仅在用户明确勾选后
    执行。数据库读取使用 SQLite Online Backup API，绝不写入浏览器源数据库。
    """

    GLOBAL_WHITE_SET = frozenset(
        {
            "google.com",
            "google.com.hk",
            "gstatic.com",
            "googleapis.com",
            "apple.com",
            "icloud.com",
            "microsoft.com",
            "bing.com",
            "msn.com",
        }
    )
    _SKIP_DIRS = frozenset(
        {
            "windows",
            "program files",
            "program files (x86)",
            "programdata",
            "recovery",
            "$recycle.bin",
            "system volume information",
            "perflogs",
            "intel",
            "amd",
            "nvidia",
            "msocache",
        }
    )
    _CHROMIUM_LAYOUTS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
        ("Chrome", ("Google", "Chrome", "User Data")),
        ("Chrome Beta", ("Google", "Chrome Beta", "User Data")),
        ("Chrome Dev", ("Google", "Chrome Dev", "User Data")),
        ("Chrome Canary", ("Google", "Chrome SxS", "User Data")),
        ("Chrome for Testing", ("Google", "Chrome for Testing", "User Data")),
        ("Chromium", ("Chromium", "User Data")),
        ("Edge", ("Microsoft", "Edge", "User Data")),
        ("Edge Beta", ("Microsoft", "Edge Beta", "User Data")),
        ("Edge Dev", ("Microsoft", "Edge Dev", "User Data")),
        ("Edge Canary", ("Microsoft", "Edge SxS", "User Data")),
        ("Brave", ("BraveSoftware", "Brave-Browser", "User Data")),
        ("360极速X", ("360chromeX", "Chrome", "User Data")),
        (
            "Arc",
            (
                "Packages",
                "TheBrowserCompany.Arc_tchbfspa9nw8p",
                "LocalCache",
                "Local",
                "Arc",
                "User Data",
            ),
        ),
    )
    _diagnostics: List[Dict[str, str]] = []
    _diagnostic_lock = threading.Lock()

    @classmethod
    def _reset_diagnostics(cls) -> None:
        with cls._diagnostic_lock:
            cls._diagnostics = []

    @staticmethod
    def _diagnostic_profile_label(profile: Dict[str, str]) -> str:
        """诊断只保留 Profile 技术标识，避免复制时携带 Local State 中的账号显示名。"""
        browser_name = str(profile.get("b", "未知浏览器"))[:80]
        profile_name = re.split(r"[（(]", str(profile.get("p", "未知配置")), maxsplit=1)[0].strip()[:80]
        return f"{browser_name} / {profile_name or 'Profile'}"

    @staticmethod
    def _safe_error_summary(exc: BaseException) -> str:
        """诊断保留可行动的错误类型/代码，不复制可能含用户名或路径的异常原文。"""
        code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
        return f"{type(exc).__name__}" + (f"（错误代码 {code}）" if code is not None else "")

    @classmethod
    def _record(cls, level: str, stage: str, message: str) -> None:
        event = {"level": level, "stage": stage, "message": message[:500]}
        with cls._diagnostic_lock:
            cls._diagnostics.append(event)
            if len(cls._diagnostics) > 200:
                cls._diagnostics = cls._diagnostics[-200:]
        log_method = logger.warning if level in {"warning", "error"} else logger.info
        log_method("[%s] %s", stage, event["message"])

    @classmethod
    def diagnostics_text(cls) -> str:
        with cls._diagnostic_lock:
            events = list(cls._diagnostics[-80:])
        if not events:
            return "诊断信息：尚未执行扫描。"
        lines = [f"浏览器痕迹分析诊断（{APP_VERSION}）"]
        for event in events:
            lines.append(f"[{event['level'].upper()}][{event['stage']}] {event['message']}")
        return "\n".join(lines)


    @staticmethod
    def _normalise_path_key(path: Path) -> str:
        try:
            return os.path.normcase(str(path.resolve()))
        except OSError:
            return os.path.normcase(str(path.absolute()))

    @staticmethod
    def _get_windows_drives() -> List[Path]:
        """只返回固定盘和可移动盘，排除网络盘以避免企业网络扫描卡顿。"""
        drives: List[Path] = []
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            candidate = Path(f"{letter}:\\")
            try:
                if not candidate.is_dir():
                    continue
                if sys.platform == "win32":
                    try:
                        import ctypes

                        drive_type = ctypes.windll.kernel32.GetDriveTypeW(str(candidate))
                        # DRIVE_REMOVABLE=2, DRIVE_FIXED=3
                        if drive_type not in (2, 3):
                            continue
                    except (AttributeError, OSError):
                        pass
                drives.append(candidate)
            except (OSError, PermissionError):
                continue
        return drives

    @classmethod
    def _chromium_candidate_dirs(cls, local_app_data: Path) -> List[Tuple[str, Path]]:
        return [(name, local_app_data.joinpath(*parts)) for name, parts in cls._CHROMIUM_LAYOUTS]

    @staticmethod
    def _load_profile_names(user_data_path: Path) -> Dict[str, str]:
        local_state = user_data_path / "Local State"
        try:
            with local_state.open("r", encoding="utf-8", errors="ignore") as file_handler:
                data = json.load(file_handler)
            info_cache = data.get("profile", {}).get("info_cache", {})
            if not isinstance(info_cache, dict):
                return {}
            return {
                str(profile_id): str(info.get("name", "")).strip()
                for profile_id, info in info_cache.items()
                if isinstance(info, dict) and str(info.get("name", "")).strip()
            }
        except (OSError, ValueError, TypeError):
            return {}

    @staticmethod
    def _is_valid_user_data(path: Path) -> bool:
        if not path.is_dir():
            return False
        try:
            return any(sub.is_dir() and (sub / "History").is_file() for sub in path.iterdir())
        except (OSError, PermissionError):
            return False

    @classmethod
    def _collect_chrome_profiles(
        cls, base: Path, browser_name: str, seen_paths: Set[str], source: str
    ) -> List[Dict[str, str]]:
        found: List[Dict[str, str]] = []
        profile_names = cls._load_profile_names(base)
        try:
            for sub in base.iterdir():
                if not sub.is_dir() or not (sub / "History").is_file():
                    continue
                path_key = cls._normalise_path_key(sub)
                if path_key in seen_paths:
                    continue
                seen_paths.add(path_key)
                readable_name = profile_names.get(sub.name, "")
                profile_label = f"{sub.name}（{readable_name}）" if readable_name else sub.name
                found.append(
                    {
                        "b": browser_name,
                        "p": profile_label,
                        "path": str(sub),
                        "type": "C",
                        "source": source,
                    }
                )
        except (OSError, PermissionError) as exc:
            cls._record("warning", "发现", f"{browser_name} 配置目录不可枚举：{cls._safe_error_summary(exc)}")
        return found

    @classmethod
    def _collect_firefox_profiles(
        cls, profiles_dir: Path, seen_paths: Set[str], source: str, browser_name: str = "Firefox"
    ) -> List[Dict[str, str]]:
        found: List[Dict[str, str]] = []
        try:
            for sub in profiles_dir.iterdir():
                if not sub.is_dir() or not (sub / "places.sqlite").is_file():
                    continue
                path_key = cls._normalise_path_key(sub)
                if path_key in seen_paths:
                    continue
                seen_paths.add(path_key)
                found.append(
                    {"b": browser_name, "p": sub.name, "path": str(sub), "type": "F", "source": source}
                )
        except (OSError, PermissionError) as exc:
            cls._record("warning", "发现", f"{browser_name} 配置目录不可枚举：{cls._safe_error_summary(exc)}")
        return found

    @classmethod
    def _current_windows_local_app_data_dirs(cls) -> List[Path]:
        candidates: List[Path] = []
        env_local = os.environ.get("LOCALAPPDATA", "").strip()
        if env_local:
            candidates.append(Path(env_local))
        try:
            candidates.append(Path.home() / "AppData" / "Local")
        except RuntimeError:
            pass

        unique: List[Path] = []
        keys: Set[str] = set()
        for candidate in candidates:
            key = cls._normalise_path_key(candidate)
            if key not in keys:
                keys.add(key)
                unique.append(candidate)
        return unique

    @classmethod
    def _scan_windows_current_user(cls, seen_paths: Set[str]) -> List[Dict[str, str]]:
        profiles: List[Dict[str, str]] = []
        local_dirs = cls._current_windows_local_app_data_dirs()
        if not local_dirs:
            cls._record("warning", "发现", "未获取到 LOCALAPPDATA；无法执行当前用户的标准路径扫描。")
            return profiles

        candidates_checked = 0
        for local_app_data in local_dirs:
            for browser_name, user_data_dir in cls._chromium_candidate_dirs(local_app_data):
                candidates_checked += 1
                if user_data_dir.is_dir():
                    profiles.extend(cls._collect_chrome_profiles(user_data_dir, browser_name, seen_paths, "当前用户"))

            roaming = local_app_data.parent / "Roaming" / "Mozilla" / "Firefox" / "Profiles"
            if roaming.is_dir():
                profiles.extend(cls._collect_firefox_profiles(roaming, seen_paths, "当前用户"))

        cls._record("info", "发现", f"当前用户标准路径检查完成：检查 {candidates_checked} 个 Chromium 候选目录，发现 {len(profiles)} 个配置。")
        return profiles

    @classmethod
    def _candidate_windows_user_roots(cls) -> List[Path]:
        roots: List[Path] = []
        for local_app_data in cls._current_windows_local_app_data_dirs():
            try:
                # C:\Users\name\AppData\Local -> C:\Users
                roots.append(local_app_data.parents[2])
            except IndexError:
                continue
        system_drive = os.environ.get("SystemDrive", "C:").rstrip("\\/")
        roots.append(Path(system_drive + "\\Users"))

        unique: List[Path] = []
        keys: Set[str] = set()
        for root in roots:
            key = cls._normalise_path_key(root)
            if key not in keys and root.is_dir():
                keys.add(key)
                unique.append(root)
        return unique

    @classmethod
    def _scan_windows_other_users(cls, seen_paths: Set[str]) -> List[Dict[str, str]]:
        """显式扩展模式：仅检查 Windows 用户根目录，不进行全盘递归。"""
        profiles: List[Dict[str, str]] = []
        ignored = {"public", "default", "default user", "all users", "desktop.ini"}
        checked_users = 0
        for users_root in cls._candidate_windows_user_roots():
            try:
                user_dirs = list(users_root.iterdir())
            except (OSError, PermissionError) as exc:
                cls._record("warning", "扩展发现", f"无法枚举 Windows 用户目录：{cls._safe_error_summary(exc)}")
                continue
            for user_dir in user_dirs:
                if not user_dir.is_dir() or user_dir.name.lower() in ignored:
                    continue
                checked_users += 1
                local_app_data = user_dir / "AppData" / "Local"
                if not local_app_data.is_dir():
                    continue
                for browser_name, user_data_dir in cls._chromium_candidate_dirs(local_app_data):
                    if user_data_dir.is_dir():
                        profiles.extend(cls._collect_chrome_profiles(user_data_dir, browser_name, seen_paths, "授权的跨用户搜索"))
                firefox_dir = user_dir / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles"
                if firefox_dir.is_dir():
                    profiles.extend(cls._collect_firefox_profiles(firefox_dir, seen_paths, "授权的跨用户搜索"))
        cls._record("info", "扩展发现", f"授权的跨用户路径检查完成：检查 {checked_users} 个用户目录，新增 {len(profiles)} 个配置。")
        return profiles

    @staticmethod
    def _infer_browser_name(user_data_path: Path, fallback: str = "Chromium(外置)") -> str:
        path_text = str(user_data_path).lower()
        if "edge" in path_text:
            return "Edge(外置)"
        if "brave" in path_text:
            return "Brave(外置)"
        if "chrome" in path_text:
            return "Chrome(外置)"
        if "chromium" in path_text:
            return "Chromium(外置)"
        return fallback

    @classmethod
    def _scan_portable_shallow(cls, seen_paths: Set[str], budget_seconds: float = 12.0) -> List[Dict[str, str]]:
        """显式扩展模式：在本地/可移动盘进行有时间上限的浅层便携版搜索。"""
        profiles: List[Dict[str, str]] = []
        deadline = time.monotonic() + budget_seconds

        def visit(current: Path, depth: int) -> None:
            if depth > 3 or time.monotonic() >= deadline:
                return
            try:
                with os.scandir(current) as iterator:
                    entries = list(iterator)
            except (OSError, PermissionError):
                return
            for entry in entries:
                if time.monotonic() >= deadline:
                    return
                try:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                if entry.name.lower() in cls._SKIP_DIRS or entry.name.startswith("$"):
                    continue
                path = Path(entry.path)
                try:
                    if (path / "places.sqlite").is_file():
                        path_key = cls._normalise_path_key(path)
                        if path_key not in seen_paths:
                            seen_paths.add(path_key)
                            profiles.append(
                                {"b": "Firefox(外置)", "p": path.name, "path": str(path), "type": "F", "source": "便携目录"}
                            )
                        continue
                    if (path / "History").is_file():
                        path_key = cls._normalise_path_key(path)
                        if path_key not in seen_paths:
                            seen_paths.add(path_key)
                            profiles.append(
                                {
                                    "b": cls._infer_browser_name(path.parent),
                                    "p": path.name,
                                    "path": str(path),
                                    "type": "C",
                                    "source": "便携目录",
                                }
                            )
                        continue
                    if cls._is_valid_user_data(path):
                        profiles.extend(
                            cls._collect_chrome_profiles(path, cls._infer_browser_name(path), seen_paths, "便携目录")
                        )
                        continue
                except (OSError, PermissionError):
                    continue
                visit(path, depth + 1)

        drives = cls._get_windows_drives()
        for drive in drives:
            visit(drive, 1)
        reason = "达到时间预算" if time.monotonic() >= deadline else "完成"
        cls._record("info", "扩展发现", f"本地/可移动盘便携目录搜索{reason}，新增 {len(profiles)} 个配置。")
        return profiles

    @staticmethod
    def _remaining_seconds(deadline: Optional[float], default: float = 5.0) -> float:
        if deadline is None:
            return default
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ScanBudgetExceeded("扫描时间预算已耗尽")
        return min(default, max(0.1, remaining))

    @classmethod
    def _snapshot_database(cls, db_path: Path, temp_dir: Path, deadline: Optional[float] = None) -> Optional[Path]:
        """通过 SQLite Online Backup API 建立一致的只读快照，并受单配置预算约束。"""
        try:
            if not db_path.is_file():
                cls._record("warning", "数据库", f"未找到数据库文件：{db_path.name}")
                return None
        except OSError as exc:
            cls._record("warning", "数据库", f"无法访问 {db_path.name}：{cls._safe_error_summary(exc)}")
            return None

        snapshot_deadline = min(deadline, time.monotonic() + SNAPSHOT_BUDGET_SECONDS) if deadline else time.monotonic() + SNAPSHOT_BUDGET_SECONDS
        target = temp_dir / f"audit_db_{time.time_ns()}.sqlite"
        source: Optional[sqlite3.Connection] = None
        destination: Optional[sqlite3.Connection] = None
        snapshot_ready = False
        try:
            db_uri = db_path.resolve().as_uri() + "?mode=ro"
            source = sqlite3.connect(db_uri, uri=True, timeout=cls._remaining_seconds(snapshot_deadline))
            source.execute(f"PRAGMA busy_timeout = {int(cls._remaining_seconds(snapshot_deadline) * 1000)}")
            destination = sqlite3.connect(str(target), timeout=cls._remaining_seconds(snapshot_deadline))

            def backup_progress(_: int, __: int, ___: int) -> None:
                cls._remaining_seconds(snapshot_deadline)

            source.backup(destination, pages=128, progress=backup_progress, sleep=0.02)
            destination.close()
            destination = None
            source.close()
            source = None
            snapshot_ready = True
            return target
        except ScanBudgetExceeded:
            cls._record("warning", "数据库", f"{db_path.name} 一致性快照超时，已跳过该配置。")
            return None
        except (sqlite3.Error, OSError, ValueError) as exc:
            cls._record("error", "数据库", f"{db_path.name} 一致性快照失败：{cls._safe_error_summary(exc)}")
            return None
        finally:
            if destination is not None:
                try:
                    destination.close()
                except sqlite3.Error:
                    pass
            if source is not None:
                try:
                    source.close()
                except sqlite3.Error:
                    pass
            if not snapshot_ready:
                try:
                    target.unlink(missing_ok=True)
                except OSError:
                    pass


    @classmethod
    def _collect_explicit_paths(cls, paths: List[Path], seen_paths: Set[str]) -> List[Dict[str, str]]:
        """处理用户手工选择的资料目录；支持 Profile 目录和 User Data 根目录。"""
        profiles: List[Dict[str, str]] = []
        for selected_path in paths:
            try:
                selected = selected_path.expanduser()
                if not selected.is_dir():
                    cls._record("warning", "手动路径", f"所选目录不存在或不可访问：{selected.name}")
                    continue
                if (selected / "History").is_file():
                    path_key = cls._normalise_path_key(selected)
                    if path_key not in seen_paths:
                        seen_paths.add(path_key)
                        profiles.append(
                            {
                                "b": cls._infer_browser_name(selected.parent),
                                "p": selected.name,
                                "path": str(selected),
                                "type": "C",
                                "source": "手动选择路径",
                            }
                        )
                    continue
                if (selected / "places.sqlite").is_file():
                    path_key = cls._normalise_path_key(selected)
                    if path_key not in seen_paths:
                        seen_paths.add(path_key)
                        profiles.append(
                            {"b": "Firefox(手动)", "p": selected.name, "path": str(selected), "type": "F", "source": "手动选择路径"}
                        )
                    continue
                # 用户常会选择 Google、Chrome 或 LocalAppData 等上级目录；仅做两层受控展开，
                # 不递归遍历磁盘，仍保持最小范围和可预测性能。
                user_data_candidates = [selected]
                try:
                    for child in selected.iterdir():
                        if child.is_dir():
                            user_data_candidates.append(child / "User Data")
                            for grandchild in child.iterdir():
                                if grandchild.is_dir():
                                    user_data_candidates.append(grandchild / "User Data")
                except (OSError, PermissionError) as exc:
                    cls._record("warning", "手动路径", f"无法枚举所选目录：{cls._safe_error_summary(exc)}")

                before_count = len(profiles)
                candidate_keys: Set[str] = set()
                for user_data_dir in user_data_candidates:
                    candidate_key = cls._normalise_path_key(user_data_dir)
                    if candidate_key in candidate_keys or not cls._is_valid_user_data(user_data_dir):
                        continue
                    candidate_keys.add(candidate_key)
                    profiles.extend(
                        cls._collect_chrome_profiles(
                            user_data_dir,
                            cls._infer_browser_name(user_data_dir.parent),
                            seen_paths,
                            "手动选择路径",
                        )
                    )
                if len(profiles) == before_count:
                    cls._record("warning", "手动路径", f"目录不是可识别的浏览器 Profile、User Data 或其上级目录：{selected.name}")
            except (OSError, PermissionError) as exc:
                cls._record("warning", "手动路径", f"无法读取所选目录：{cls._safe_error_summary(exc)}")
        if paths:
            cls._record("info", "手动路径", f"手动路径检查完成：新增 {len(profiles)} 个配置。")
        return profiles

    @classmethod
    def get_profiles(cls, include_extended: bool = False, extra_paths: Optional[List[Path]] = None) -> List[Dict[str, str]]:
        cls._reset_diagnostics()
        profiles: List[Dict[str, str]] = []
        seen_paths: Set[str] = set()

        if sys.platform == "win32":
            profiles.extend(cls._scan_windows_current_user(seen_paths))
            if include_extended:
                profiles.extend(cls._scan_windows_other_users(seen_paths))
                profiles.extend(cls._scan_portable_shallow(seen_paths))

        elif sys.platform == "darwin":
            home = Path.home()
            safari_path = home / "Library" / "Safari"
            if (safari_path / "History.db").is_file() or (safari_path / "Bookmarks.plist").is_file():
                profiles.append({"b": "Safari", "p": "MainSystem", "path": str(safari_path), "type": "S", "source": "当前用户"})

            mac_chromium = (
                ("Chrome", home / "Library/Application Support/Google/Chrome"),
                ("Chrome Beta", home / "Library/Application Support/Google/Chrome Beta"),
                ("Chrome Dev", home / "Library/Application Support/Google/Chrome Dev"),
                ("Chrome Canary", home / "Library/Application Support/Google/Chrome Canary"),
                ("Chrome for Testing", home / "Library/Application Support/Google/Chrome for Testing"),
                ("Chromium", home / "Library/Application Support/Chromium"),
                ("Edge", home / "Library/Application Support/Microsoft Edge"),
                ("Brave", home / "Library/Application Support/BraveSoftware/Brave-Browser"),
                ("Arc", home / "Library/Application Support/Arc/User Data"),
            )
            for browser_name, user_data_dir in mac_chromium:
                if user_data_dir.is_dir():
                    profiles.extend(cls._collect_chrome_profiles(user_data_dir, browser_name, seen_paths, "当前用户"))
            firefox_dir = home / "Library/Application Support/Firefox/Profiles"
            if firefox_dir.is_dir():
                profiles.extend(cls._collect_firefox_profiles(firefox_dir, seen_paths, "当前用户"))
            cls._record("info", "发现", f"macOS 当前用户路径检查完成：发现 {len(profiles)} 个配置。")
        else:
            cls._record("warning", "发现", f"当前系统不受支持：{sys.platform}")

        if extra_paths:
            profiles.extend(cls._collect_explicit_paths(extra_paths, seen_paths))

        profiles.sort(key=lambda item: (item["b"].lower(), item["p"].lower(), item["path"].lower()))
        cls._record("info", "发现", f"浏览器配置发现完成：共识别 {len(profiles)} 个独立配置。")
        return profiles

    @classmethod
    def _read_urls(
        cls,
        cursor: sqlite3.Cursor,
        query: str,
        profile: Dict[str, str],
        info_type: str,
        rules: Dict[str, str],
        hits: List[Tuple],
        deadline: Optional[float] = None,
    ) -> None:
        cls._remaining_seconds(deadline)
        cursor.execute(query)
        processed = 0
        while processed < MAX_URL_ROWS_PER_TABLE:
            cls._remaining_seconds(deadline)
            rows = cursor.fetchmany(min(1000, MAX_URL_ROWS_PER_TABLE - processed))
            if not rows:
                return
            processed += len(rows)
            for row in rows:
                for value in row:
                    if value:
                        cls._match(str(value), info_type, profile, rules, hits)
        cls._record(
            "warning",
            "读取限额",
            f"{cls._diagnostic_profile_label(profile)} 的 {info_type} 已读取 {MAX_URL_ROWS_PER_TABLE} 行，超出部分已跳过。",
        )

    @staticmethod
    def _table_columns(cursor: sqlite3.Cursor, table_name: str) -> Set[str]:
        cursor.execute(f"PRAGMA table_info({table_name})")
        return {str(row[1]) for row in cursor.fetchall()}

    @classmethod
    def _scan_chromium_downloads(
        cls,
        cursor: sqlite3.Cursor,
        profile: Dict[str, str],
        rules: Dict[str, str],
        hits: List[Tuple],
        deadline: Optional[float] = None,
    ) -> None:
        try:
            columns = cls._table_columns(cursor, "downloads")
            if columns:
                preferred = [column for column in ("tab_url", "url", "site_url", "referrer", "target_path", "current_path") if column in columns]
                if preferred:
                    cls._read_urls(
                        cursor,
                        "SELECT " + ", ".join(preferred) + " FROM downloads",
                        profile,
                        "下载文件",
                        rules,
                        hits,
                        deadline,
                    )
        except sqlite3.Error as exc:
            cls._record("info", "下载记录", f"{cls._diagnostic_profile_label(profile)} 的 downloads 表不可用：{cls._safe_error_summary(exc)}")

        try:
            cls._read_urls(cursor, "SELECT url FROM downloads_url_chains", profile, "下载文件", rules, hits, deadline)
        except sqlite3.Error:
            # 旧版 Chromium 可能没有 downloads_url_chains，此处属于可预期兼容分支。
            pass

    @classmethod
    def _scan_chromium(
        cls,
        profile: Dict[str, str],
        rules: Dict[str, str],
        temp_dir: Path,
        hits: List[Tuple],
        deadline: Optional[float] = None,
    ) -> None:
        profile_path = Path(profile["path"])
        snapshot = cls._snapshot_database(profile_path / "History", temp_dir, deadline)
        if snapshot is None:
            return
        connection: Optional[sqlite3.Connection] = None
        try:
            connection = sqlite3.connect(
                snapshot.as_uri() + "?mode=ro", uri=True, timeout=cls._remaining_seconds(deadline)
            )
            cursor = connection.cursor()
            cls._read_urls(
                cursor, "SELECT url FROM urls WHERE url IS NOT NULL", profile, "历史记录", rules, hits, deadline
            )
            cls._scan_chromium_downloads(cursor, profile, rules, hits, deadline)
        except ScanBudgetExceeded:
            raise
        except sqlite3.Error as exc:
            cls._record("error", "数据库", f"{cls._diagnostic_profile_label(profile)} 读取失败：{cls._safe_error_summary(exc)}")
        finally:
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass
            try:
                snapshot.unlink(missing_ok=True)
            except OSError as exc:
                cls._record("warning", "清理", f"临时数据库清理失败：{cls._safe_error_summary(exc)}")

        if deadline is not None and time.monotonic() >= deadline:
            raise ScanBudgetExceeded("历史数据库读取后时间预算已耗尽")

        bookmark_path = profile_path / "Bookmarks"
        if bookmark_path.is_file():
            try:
                with bookmark_path.open("r", encoding="utf-8", errors="ignore") as file_handler:
                    data = json.load(file_handler)

                def walk(node: object) -> None:
                    if not isinstance(node, dict):
                        return
                    value = node.get("url")
                    if isinstance(value, str):
                        cls._match(value, "浏览器书签", profile, rules, hits)
                    children = node.get("children", [])
                    if isinstance(children, list):
                        for child in children:
                            walk(child)

                roots = data.get("roots", {}) if isinstance(data, dict) else {}
                if isinstance(roots, dict):
                    for root in roots.values():
                        walk(root)
            except (OSError, ValueError, TypeError) as exc:
                cls._record("warning", "书签", f"{cls._diagnostic_profile_label(profile)} 书签解析失败：{cls._safe_error_summary(exc)}")

    @classmethod
    def _scan_firefox(
        cls,
        profile: Dict[str, str],
        rules: Dict[str, str],
        temp_dir: Path,
        hits: List[Tuple],
        deadline: Optional[float] = None,
    ) -> None:
        profile_path = Path(profile["path"])
        snapshot = cls._snapshot_database(profile_path / "places.sqlite", temp_dir, deadline)
        if snapshot is None:
            return
        connection: Optional[sqlite3.Connection] = None
        try:
            connection = sqlite3.connect(
                snapshot.as_uri() + "?mode=ro", uri=True, timeout=cls._remaining_seconds(deadline)
            )
            cursor = connection.cursor()
            cls._read_urls(
                cursor, "SELECT url FROM moz_places WHERE url IS NOT NULL", profile, "历史记录", rules, hits, deadline
            )
            try:
                cls._read_urls(
                    cursor,
                    """
                    SELECT DISTINCT mp.url FROM moz_annos ma
                    JOIN moz_places mp ON ma.place_id = mp.id
                    WHERE ma.anno_attribute_id IN (
                        SELECT id FROM moz_anno_attributes WHERE name LIKE '%download%'
                    )
                    UNION
                    SELECT DISTINCT url FROM moz_places
                    WHERE url LIKE 'file://%' OR url LIKE '%content-signature%'
                    """,
                    profile,
                    "下载文件",
                    rules,
                    hits,
                    deadline,
                )
            except sqlite3.Error:
                pass
        except ScanBudgetExceeded:
            raise
        except sqlite3.Error as exc:
            cls._record("error", "数据库", f"{cls._diagnostic_profile_label(profile)} 读取失败：{cls._safe_error_summary(exc)}")
        finally:
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass
            try:
                snapshot.unlink(missing_ok=True)
            except OSError as exc:
                cls._record("warning", "清理", f"临时数据库清理失败：{cls._safe_error_summary(exc)}")

    @classmethod
    def _scan_safari(
        cls,
        profile: Dict[str, str],
        rules: Dict[str, str],
        temp_dir: Path,
        hits: List[Tuple],
        deadline: Optional[float] = None,
    ) -> None:
        profile_path = Path(profile["path"])
        snapshot = cls._snapshot_database(profile_path / "History.db", temp_dir, deadline)
        if snapshot is not None:
            connection: Optional[sqlite3.Connection] = None
            try:
                connection = sqlite3.connect(
                    snapshot.as_uri() + "?mode=ro", uri=True, timeout=cls._remaining_seconds(deadline)
                )
                cursor = connection.cursor()
                try:
                    query = """
                        SELECT DISTINCT history_items.url FROM history_items
                        INNER JOIN history_visits ON history_items.id = history_visits.history_item
                    """
                    cls._read_urls(cursor, query, profile, "历史记录", rules, hits, deadline)
                except sqlite3.Error:
                    cls._read_urls(cursor, "SELECT url FROM history_items", profile, "历史记录", rules, hits, deadline)
            except sqlite3.Error as exc:
                cls._record("error", "数据库", f"Safari 读取失败：{cls._safe_error_summary(exc)}")
            finally:
                if connection is not None:
                    try:
                        connection.close()
                    except sqlite3.Error:
                        pass
                try:
                    snapshot.unlink(missing_ok=True)
                except OSError as exc:
                    cls._record("warning", "清理", f"临时数据库清理失败：{cls._safe_error_summary(exc)}")

        plist_path = profile_path / "Bookmarks.plist"
        if plist_path.is_file():
            try:
                with plist_path.open("rb") as file_handler:
                    plist_data = plistlib.load(file_handler)

                def walk(node: object) -> None:
                    if isinstance(node, dict):
                        value = node.get("URLString")
                        if isinstance(value, str):
                            cls._match(value, "浏览器书签", profile, rules, hits)
                        for value in node.values():
                            walk(value)
                    elif isinstance(node, list):
                        for child in node:
                            walk(child)

                walk(plist_data)
            except (OSError, ValueError, TypeError) as exc:
                cls._record("warning", "书签", f"Safari 书签解析失败：{cls._safe_error_summary(exc)}")

    @classmethod
    def scan(cls, profile: Dict[str, str], rules: Dict[str, str], temp_dir: Path) -> List[Tuple]:
        """扫描单个 Profile；任何异常均仅影响当前配置，绝不终止全局扫描。"""
        hits: List[Tuple] = []
        started_at = time.monotonic()
        deadline = started_at + PROFILE_SCAN_BUDGET_SECONDS
        profile_label = cls._diagnostic_profile_label(profile)
        try:
            if profile["type"] == "C":
                cls._scan_chromium(profile, rules, temp_dir, hits, deadline)
            elif profile["type"] == "F":
                cls._scan_firefox(profile, rules, temp_dir, hits, deadline)
            elif profile["type"] == "S":
                cls._scan_safari(profile, rules, temp_dir, hits, deadline)
        except ScanBudgetExceeded:
            cls._record("warning", "扫描限时", f"{profile_label} 超过 {PROFILE_SCAN_BUDGET_SECONDS:.0f} 秒预算，已跳过剩余记录并继续下一个配置。")
        except (OSError, sqlite3.Error, ValueError, TypeError) as exc:
            cls._record("error", "配置隔离", f"{profile_label} 已跳过：{cls._safe_error_summary(exc)}")
        except Exception as exc:  # 最后的配置级保护，防止未知格式破坏整批审计。
            logger.exception("Profile 扫描异常：%s", profile_label)
            cls._record("error", "配置隔离", f"{profile_label} 出现未预期异常，已跳过：{cls._safe_error_summary(exc)}")
        finally:
            elapsed = time.monotonic() - started_at
            cls._record("info", "扫描进度", f"{profile_label} 已处理，用时 {elapsed:.1f} 秒，命中 {len(hits)} 条。")
        return hits

    @classmethod
    def _match(cls, url: str, info_type: str, profile: Dict[str, str], rules: Dict[str, str], hits: List[Tuple]) -> None:
        if not url or len(hits) >= MAX_MATCHES or len(url) > 8192:
            return
        try:
            parsed = urlparse(url)
            domain = (parsed.hostname or "").lower()
            if not domain:
                return
            labels = domain.split(".")
            for index in range(len(labels)):
                if ".".join(labels[index:]) in cls.GLOBAL_WHITE_SET:
                    return
            for index in range(len(labels)):
                candidate = ".".join(labels[index:])
                if "." in candidate and candidate in rules:
                    hits.append((profile["b"], profile["p"], info_type, rules[candidate], url))
                    return
        except (ValueError, TypeError):
            return


# =================================================
# 3. GUI
# =================================================
class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"浏览器痕迹分析 v{APP_VERSION}")
        self.geometry("540x305" if sys.platform == "win32" else "540x285")
        self.resizable(False, False)

        self.all_hits: List[Tuple] = []
        self.is_scanning = False
        self.generated_reports: List[Path] = []
        self.queue: queue.Queue = queue.Queue()
        self.core_temp_dir = Path(tempfile.mkdtemp(prefix="browser_audit_"))
        self.report_dir = self.core_temp_dir / "reports"
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.extended_scan_var = tk.BooleanVar(value=False)
        self.selected_paths: List[Path] = []
        self.last_profile_count = 0
        self.last_processed_count = 0

        ResourceManager.initialize()
        self.protocol("WM_DELETE_WINDOW", self.on_exit)
        self._build_ui()
        self.after(100, self._process_queue)

    def _build_ui(self) -> None:
        header = tk.Frame(self, pady=10)
        header.pack(fill=tk.X, padx=15)
        tk.Label(header, text="TRACE AUDITOR PRO", font=("Arial", 8, "bold"), fg="#d9363e").pack(anchor="w")
        tk.Label(header, text="浏览器痕迹分析", font=("Arial", 14, "bold")).pack(anchor="w")
        tk.Label(
            header,
            text="v1.1.8：多浏览器兼容识别、异常 Profile 隔离与可复制诊断",
            font=("Arial", 9),
            fg="#555",
        ).pack(anchor="w", pady=(2, 0))

        control_box = tk.Frame(self)
        control_box.pack(fill=tk.X, padx=15, pady=(2, 4))
        self.btn_run = tk.Button(control_box, text="开始检测", command=self.run, font=("Arial", 10, "bold"), height=2)
        self.btn_run.pack(fill=tk.X, expand=True)

        tk.Checkbutton(
            self,
            text="扩展兼容搜索（经授权后检查同机其他用户目录与本地/可移动盘便携版）",
            variable=self.extended_scan_var,
            anchor="w",
            justify=tk.LEFT,
            font=("Arial", 9),
        ).pack(fill=tk.X, padx=15, pady=(2, 0))

        action_box = tk.Frame(self)
        action_box.pack(fill=tk.X, padx=15, pady=(2, 0))
        tk.Button(action_box, text="选择浏览器数据目录", command=self.choose_browser_directory, font=("Arial", 9)).pack(side=tk.LEFT)
        self.btn_copy_diagnostic = tk.Button(action_box, text="复制诊断信息", command=self.copy_diagnostics, font=("Arial", 9))
        self.btn_copy_diagnostic.pack(side=tk.LEFT, padx=(8, 0))
        tk.Label(
            action_box,
            text="诊断不包含 URL、Cookie、账号或浏览器数据库内容。",
            fg="#666",
            font=("Arial", 8),
        ).pack(side=tk.LEFT, padx=(10, 0))

        self.pbar = ttk.Progressbar(self, mode="determinate")
        self.pbar.pack(fill=tk.X, padx=15, pady=(9, 0))
        self.status_lbl = tk.Label(self, text="系统就绪：默认仅检查当前用户的标准浏览器路径。", fg="#555", font=("Arial", 9), anchor="w", justify=tk.LEFT, wraplength=510)
        self.status_lbl.pack(fill=tk.X, padx=15, pady=(5, 0))

    def choose_browser_directory(self) -> None:
        initial_dir = os.environ.get("LOCALAPPDATA", str(Path.home()))
        directory = filedialog.askdirectory(title="选择 Chrome Profile 或 User Data 文件夹", initialdir=initial_dir, mustexist=True)
        if not directory:
            return
        selected = Path(directory)
        selected_key = ScannerCore._normalise_path_key(selected)
        if all(ScannerCore._normalise_path_key(path) != selected_key for path in self.selected_paths):
            self.selected_paths.append(selected)
        self.status_lbl.config(text=f"已添加手动路径：{selected.name}。开始检测时将一并检查；已添加 {len(self.selected_paths)} 个路径。")

    def copy_diagnostics(self) -> None:
        diagnostic = ScannerCore.diagnostics_text()
        try:
            self.clipboard_clear()
            self.clipboard_append(diagnostic)
            self.update()
            self.status_lbl.config(text="诊断信息已复制。请直接粘贴反馈；其中不含历史网址或账号数据。")
        except tk.TclError as exc:
            messagebox.showerror("复制失败", f"无法写入剪贴板：{exc}")

    def run(self) -> None:
        self.btn_run.config(state="disabled")
        self.pbar["value"] = 0
        self.all_hits.clear()
        self.is_scanning = True
        self.last_profile_count = 0
        self.last_processed_count = 0
        include_extended = self.extended_scan_var.get()
        extra_paths = list(self.selected_paths)
        rules = ResourceManager.load_audit_rules()

        def task() -> None:
            try:
                profiles = ScannerCore.get_profiles(include_extended=include_extended, extra_paths=extra_paths)
                self.queue.put(("discovery", len(profiles)))
                if not profiles:
                    self.queue.put(("done", []))
                    return

                final_results: List[Tuple] = []
                processed_count = 0
                session_deadline = time.monotonic() + SESSION_SCAN_BUDGET_SECONDS
                for index, profile in enumerate(profiles):
                    if not self.is_scanning:
                        break
                    if time.monotonic() >= session_deadline:
                        remaining_count = len(profiles) - processed_count
                        ScannerCore._record(
                            "warning",
                            "总扫描限时",
                            f"已达到 {SESSION_SCAN_BUDGET_SECONDS:.0f} 秒总预算，跳过剩余 {remaining_count} 个配置。",
                        )
                        self.queue.put(("msg", f"达到总扫描时间预算，已跳过剩余 {remaining_count} 个配置。"))
                        break
                    self.queue.put(("msg", f"正在读取（{index + 1}/{len(profiles)}）：{profile['b']} → {profile['p']}"))
                    profile_hits = ScannerCore.scan(profile, rules, self.core_temp_dir)
                    remaining_hits = MAX_MATCHES - len(final_results)
                    if remaining_hits > 0:
                        final_results.extend(profile_hits[:remaining_hits])
                    if len(final_results) >= MAX_MATCHES:
                        ScannerCore._record(
                            "warning",
                            "命中限额",
                            f"已达到全局命中上限 {MAX_MATCHES} 条，停止扫描剩余配置以保护内存。",
                        )
                        processed_count += 1
                        self.queue.put(("progress", int(processed_count / len(profiles) * 100)))
                        break
                    processed_count += 1
                    self.queue.put(("progress", int(processed_count / len(profiles) * 100)))
                    self.queue.put(("msg", f"已处理 {processed_count}/{len(profiles)}：{profile['b']} → {profile['p']}"))

                if self.is_scanning:
                    self.queue.put(("scan_summary", processed_count))
                    self.queue.put(("done", final_results))
            except Exception as exc:  # 保留最上层保护，完整异常会进入日志与诊断。
                logger.exception("扫描核心异常")
                ScannerCore._record("error", "扫描", f"扫描中断：{ScannerCore._safe_error_summary(exc)}")
                self.queue.put(("error", str(exc)))
            finally:
                self.is_scanning = False

        threading.Thread(target=task, daemon=True, name="browser-audit-scan").start()

    def execute_instant_report(self) -> None:
        if not self.all_hits:
            return
        target_path = self.report_dir / f"Browser_Audit_Report_{time.time_ns()}.html"
        unique_hits: List[Tuple] = []
        seen: Set[Tuple[str, str, str, str]] = set()
        for hit in self.all_hits:
            key = (hit[0], hit[1], hit[2], hit[4])
            if key not in seen:
                seen.add(key)
                unique_hits.append(hit)

        html_content = [
            "<!DOCTYPE html><html><head><meta charset='utf-8'><title>浏览器痕迹分析报告</title>",
            "<style>body{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:25px;background:#f5f7fa;}"
            ".container{max-width:1500px;margin:auto;background:#fff;padding:30px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,.06);}"
            "h1{color:#2c3e50;text-align:center;border-bottom:2px solid #1890ff;padding-bottom:15px;margin-top:0;font-size:24px;}"
            ".summary{font-size:14px;color:#555;margin-bottom:20px;display:flex;justify-content:space-between;background:#e6f7ff;padding:12px 20px;border-radius:4px;border-left:4px solid #1890ff;}"
            ".highlight{color:#d9363e;font-weight:bold;font-size:16px;}table{width:100%;border-collapse:collapse;table-layout:fixed;}"
            "th:nth-child(1),td:nth-child(1){width:10%;text-align:center;}th:nth-child(2),td:nth-child(2){width:12%;text-align:center;}"
            "th:nth-child(3),td:nth-child(3){width:10%;text-align:center;}th:nth-child(4),td:nth-child(4){width:13%;text-align:center;}th:nth-child(5),td:nth-child(5){width:55%;}"
            "th,td{padding:12px;border-bottom:1px solid #f0f0f0;font-size:13px;word-wrap:break-word;}th{background:#1890ff;color:white;font-weight:600;text-align:center;}"
            ".url-cell{color:#2c3e50;font-family:Consolas,monospace;user-select:all;background:#fafafa;padding:6px 10px;border-radius:4px;border:1px solid #e8e8e8;}"
            "</style></head><body><div class='container'>",
            f"<h1>浏览器痕迹分析报告（v{APP_VERSION}）</h1>",
            f"<div class='summary'><span>生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>"
            f"<span>匹配记录：<span class='highlight'>{len(unique_hits)}</span> 条</span></div>",
            "<table><tr><th>浏览器</th><th>配置分身</th><th>记录类型</th><th>审计分类</th><th>详细地址（可复制）</th></tr>",
        ]
        for hit in unique_hits:
            safe_values = [html.escape(str(value), quote=True) for value in hit]
            html_content.append(
                f"<tr><td>{safe_values[0]}</td><td>{safe_values[1]}</td><td>{safe_values[2]}</td>"
                f"<td><strong>{safe_values[3]}</strong></td><td><div class='url-cell' title='{safe_values[4]}'>{safe_values[4]}</div></td></tr>"
            )
        html_content.append("</table></div></body></html>")

        try:
            target_path.write_text("".join(html_content), encoding="utf-8")
            self.generated_reports.append(target_path)
            if sys.platform == "darwin":
                subprocess.Popen(["open", str(target_path)])
            else:
                webbrowser.open(target_path.as_uri())
        except OSError as exc:
            ScannerCore._record("error", "报告", f"报告生成失败：{ScannerCore._safe_error_summary(exc)}")
            messagebox.showerror("报告生成失败", str(exc))

    def _process_queue(self) -> None:
        try:
            while True:
                try:
                    message_type, value = self.queue.get_nowait()
                except queue.Empty:
                    break
                if message_type == "progress":
                    self.pbar["value"] = value
                elif message_type == "msg":
                    self.status_lbl.config(text=value)
                elif message_type == "discovery":
                    self.last_profile_count = int(value)
                    self.status_lbl.config(text=f"已识别 {self.last_profile_count} 个浏览器配置，正在读取数据库。")
                elif message_type == "scan_summary":
                    self.last_processed_count = int(value)
                elif message_type == "done":
                    self.btn_run.config(state="normal")
                    self.all_hits = value
                    if self.last_profile_count == 0:
                        self.status_lbl.config(text="未识别浏览器配置。请复制诊断信息；必要时在已获授权后勾选“扩展兼容搜索”再试。")
                        messagebox.showwarning(
                            "未识别浏览器配置",
                            "未识别到可读取的浏览器配置。\n\n"
                            "请点击“复制诊断信息”并反馈文本；文本不含网址、Cookie 或账号数据。\n"
                            "若设备由远程工具/管理员账户运行，请在获得授权后勾选扩展兼容搜索后重试。",
                        )
                    elif self.all_hits:
                        self.execute_instant_report()
                        self.status_lbl.config(text=f"完成：已处理 {self.last_processed_count}/{self.last_profile_count} 个配置，命中 {len(self.all_hits)} 条记录，报告已在浏览器打开。")
                    else:
                        self.status_lbl.config(text=f"扫描完成：已处理 {self.last_processed_count}/{self.last_profile_count} 个配置，未发现符合当前规则的留痕。")
                        messagebox.showinfo("检测结果", f"已处理 {self.last_processed_count}/{self.last_profile_count} 个浏览器配置，但没有匹配到当前规则库中的记录。")
                elif message_type == "error":
                    self.btn_run.config(state="normal")
                    self.status_lbl.config(text=f"扫描异常中断：{value}。请复制诊断信息反馈。")
                    messagebox.showerror("扫描异常", f"扫描异常中断：{value}\n\n请复制诊断信息反馈。")
        finally:
            try:
                self.after(100, self._process_queue)
            except tk.TclError:
                pass

    def on_exit(self) -> None:
        self.is_scanning = False
        for report_path in self.generated_reports:
            try:
                report_path.unlink(missing_ok=True)
            except OSError as exc:
                logger.warning("报告仍被占用，未能删除：%s", exc)
        try:
            shutil.rmtree(self.core_temp_dir, ignore_errors=False)
        except OSError as exc:
            logger.warning("临时目录仍被占用，未能删除：%s", exc)
        self.destroy()


if __name__ == "__main__":
    App().mainloop()
