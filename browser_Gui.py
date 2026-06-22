import os
import sys
import time
import json
import html
import shutil
import sqlite3
import threading
import queue
import tempfile
import webbrowser  
import subprocess
import logging
import plistlib
import re
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import tkinter as tk
from tkinter import ttk, messagebox
from typing import List, Dict, Tuple, Optional, Set

# =================================================
# 0. 全局配置与高级日志配置
# =================================================
CACHE_VERSION = 11.6  # 标记 v1.1.6 专版内核

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

gui_warning_queue = queue.Queue()

# 核心内置硬编码规则库
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
    "dreamina.capcut.com": "专项审计目标"
}

def get_base_directory() -> Path:
    if getattr(sys, 'frozen', False):
        if sys.platform == 'darwin':
            exec_dir = Path(sys.executable).parent
            if exec_dir.name == "MacOS" and exec_dir.parent.name == "Contents":
                app_path = exec_dir.parent.parent
                parent_dir = app_path.parent
                is_translocation = "AppTranslocation" in str(parent_dir) or "/var/folders" in str(parent_dir)
                if is_translocation:
                    return Path(tempfile.gettempdir())
                return parent_dir
            return Path(sys.executable).parent
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent

BASE_DIR = get_base_directory()
CACHE_FILE = BASE_DIR / "rules.cache.json"

class ResourceManager:
    @staticmethod
    def initialize():
        pass

    @staticmethod
    def is_browser_running() -> List[str]:
        browsers = ["chrome", "msedge", "brave", "360se", "360chrome", "firefox", "safari"]
        running = []
        try:
            if sys.platform == 'win32':
                tasks = os.popen('tasklist /fo csv /nh').read().lower()
                for b in browsers:
                    if f'"{b}.exe"' in tasks:
                        running.append(b)
            else:
                tasks_raw = subprocess.check_output(
                    ["ps", "-e", "-o", "comm="],
                    text=True,
                    errors="ignore"
                ).splitlines()
                for line in tasks_raw:
                    proc_name = Path(line.strip()).name.lower()
                    for b in browsers:
                        if b not in running:
                            if proc_name == b or proc_name.startswith(f"{b}."):
                                running.append(b)
        except Exception as e:
            logger.debug(f"进程检测异常: {e}")
        return running

    @staticmethod
    def load_audit_rules() -> Dict[str, str]:
        rules = {}
        possible_files = []
        
        if getattr(sys, 'frozen', False):
            if sys.platform == 'darwin':
                exec_dir = Path(sys.executable).parent
                if exec_dir.name == "MacOS" and exec_dir.parent.name == "Contents":
                    possible_files.append(exec_dir.parent.parent.parent / "custom-domains.conf")
            possible_files.append(Path(sys.executable).parent / "custom-domains.conf")
        else:
            possible_files.append(Path(__file__).resolve().parent / "custom-domains.conf")
            
        docs_dir = Path.home() / "Documents" / "浏览器痕迹分析配置"
        docs_conf = docs_dir / "custom-domains.conf"
        possible_files.append(docs_conf)
        
        if not docs_conf.exists():
            try:
                docs_dir.mkdir(parents=True, exist_ok=True)
                docs_conf.write_text(
                    "# 专项规则库 (自定义扩展区)\n"
                    "# 💡 【macOS 用户提示】\n"
                    "# 软件会优先尝试读取 App 同目录下的 custom-domains.conf。\n"
                    "# 由于 macOS 的 App Translocation（应用随机转位）安全机制，在某些情况下程序实际运行路径会被系统重定向，\n"
                    "# 导致可能无法访问放置在 .app 旁边的配置文件。\n"
                    "# 为确保规则库始终可用，软件会自动在本目录（文稿/Documents/浏览器痕迹分析配置/）下维护一份配置文件。\n"
                    "# 您只需修改或粘贴自定义规则至此，后续扫描时即可自动加载、增量合并并生效。\n"
                    "# ------------------------------------------------\n"
                    "# 格式范例：\n"
                    "# example.com=自定义分类\n", 
                    encoding="utf-8"
                )
            except Exception:
                pass

        server_pattern = re.compile(r"^server=/([^/]+)/")
        for f in possible_files:
            if f and f.exists():
                try:
                    with open(f, 'r', encoding='utf-8', errors='ignore') as file_handler:
                        for line in file_handler:
                            line = line.strip()
                            if not line or line.startswith("#"): continue
                            if line.startswith("server="):
                                match = server_pattern.match(line)
                                if match:
                                    domain = match.group(1).strip().lower()
                                    if len(domain) >= 4 and "." in domain:
                                        rules[domain] = "专项审计目标"
                            elif "=" in line:
                                k, v = line.split("=", 1)
                                k = k.strip().lower()
                                if "." in k:
                                    rules[k] = v.strip()
                except Exception as e:
                    logger.error(f"解析外部规则库异常 [{f}]: {e}")

        for k, v in DEFAULT_INTERNAL_RULES.items():
            if k not in rules:
                rules[k] = v
                
        return rules

# =================================================
# 2. 扫描内核 (纯流式安全穿透架构)
# =================================================
class ScannerCore:
    GLOBAL_WHITE_SET = frozenset({
        "google.com", "google.com.hk", "gstatic.com", "googleapis.com", 
        "apple.com", "icloud.com", "microsoft.com", "bing.com", "msn.com"
    })

    # 仅跳过真正的系统级噪音目录，不屏蔽任何用户数据目录
    # ⚠️ 注意：故意移除了 documents/downloads/videos/music/pictures，
    #    因为 WTG 用户常将便携浏览器放在这些目录下，屏蔽会造成漏检
    _SKIP_DIRS = frozenset({
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
    })

    @staticmethod
    def _get_current_username() -> str:
        """安全获取当前用户名，兼容 WTG / 服务账户等边缘环境。"""
        try:
            return os.getlogin()
        except Exception:
            pass
        for env_key in ("USERNAME", "USER", "LOGNAME"):
            val = os.environ.get(env_key, "").strip()
            if val:
                return val
        return Path.home().name

    @staticmethod
    def _get_windows_drives() -> List[Path]:
        """枚举 Windows 当前所有已挂载、可访问的盘符。"""
        drives = []
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            candidate = Path(f"{letter}:\\")
            try:
                if candidate.is_dir():
                    drives.append(candidate)
            except (OSError, PermissionError):
                pass
        return drives

    @staticmethod
    def _is_valid_user_data(path: Path) -> bool:
        """
        通过特征指纹判定是否为合法的 Chrome/Edge 系 User Data 根目录。
        条件：目录下至少存在一个含 History 文件的子目录（即至少一个 Profile 分身）。
        """
        if not path.is_dir():
            return False
        try:
            for sub in path.iterdir():
                if sub.is_dir() and (sub / "History").exists():
                    return True
        except (PermissionError, OSError):
            pass
        return False

    @staticmethod
    def _infer_browser_name(user_data_path: Path, fallback: str = "Chrome(外置)") -> str:
        """
        通过路径关键字 + 内部文件特征，安全地推断外置 Chromium 系浏览器的具体名称。
        所有 iterdir() 操作均有 try/except 保护，不会因权限问题中断上层流程。
        """
        path_str = str(user_data_path).lower()
        if "edge" in path_str:
            return "Edge(外置)"
        if "brave" in path_str:
            return "Brave(外置)"
        if "chrome" in path_str:
            return "Chrome(外置)"

        # 路径名无法判断时，进一步检查内部文件特征区分 Edge vs Chrome
        # Edge 的 User Data 根下通常有 Edge-specific 的配置文件
        default_dir = user_data_path / "Default"
        if (default_dir / "Edge Preferences").exists():
            return "Edge(外置)"

        # 检查根目录下的 .json/.dat 文件名是否含 edge 关键字
        try:
            for f in user_data_path.iterdir():
                if f.is_file() and f.suffix in (".json", ".dat"):
                    if "edge" in f.name.lower():
                        return "Edge(外置)"
        except (PermissionError, OSError):
            pass

        return fallback

    @staticmethod
    def _collect_chrome_profiles(base: Path, browser_name: str,
                                  seen_paths: Set[str]) -> List[Dict[str, str]]:
        """从 User Data 根目录中枚举所有有效的 Profile 分身并去重。"""
        found = []
        try:
            for sub in base.iterdir():
                if not sub.is_dir():
                    continue
                if not (sub / "History").exists():
                    continue
                try:
                    real_path = str(sub.resolve())
                except OSError:
                    real_path = str(sub)
                if real_path in seen_paths:
                    continue
                seen_paths.add(real_path)
                found.append({
                    "b": browser_name,
                    "p": sub.name,
                    "path": str(sub),
                    "type": "C"
                })
        except (PermissionError, OSError) as e:
            logger.debug(f"枚举 Profile 分身受限 [{base}]: {e}")
        return found

    @staticmethod
    def _win_scan_standard_paths(drives: List[Path], username: str,
                                  seen_paths: Set[str]) -> List[Dict[str, str]]:
        """策略一：全盘符标准路径高速扫描，精准命中常规安装场景。"""
        profiles = []
        standard_defs = [
            (f"Users\\{username}\\AppData\\Local\\Google\\Chrome\\User Data",            "Chrome"),
            (f"Users\\{username}\\AppData\\Local\\Microsoft\\Edge\\User Data",           "Edge"),
            (f"Users\\{username}\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data", "Brave"),
            (f"Users\\{username}\\AppData\\Local\\360chromeX\\Chrome\\User Data",        "360极速X"),
            (f"Users\\{username}\\AppData\\Local\\Packages\\TheBrowserCompany.Arc_tchbfspa9nw8p\\LocalCache\\Local\\Arc\\User Data", "Arc"),
        ]
        for drive in drives:
            for rel_path, bname in standard_defs:
                base = drive / rel_path
                if ScannerCore._is_valid_user_data(base):
                    profiles.extend(
                        ScannerCore._collect_chrome_profiles(base, bname, seen_paths)
                    )
        return profiles

    @staticmethod
    def _win_scan_firefox_standard(drives: List[Path], username: str,
                                    seen_paths: Set[str]) -> List[Dict[str, str]]:
        """
        Firefox 全盘符标准 Roaming 路径扫描。
        覆盖 WTG 场景：系统盘变更后 Roaming 路径的盘符前缀也随之变化。
        """
        profiles = []
        for drive in drives:
            ff_base = drive / f"Users\\{username}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles"
            if not ff_base.exists():
                continue
            try:
                for sub in ff_base.iterdir():
                    if not sub.is_dir():
                        continue
                    if not (sub / "places.sqlite").exists():
                        continue
                    try:
                        real_path = str(sub.resolve())
                    except OSError:
                        real_path = str(sub)
                    if real_path in seen_paths:
                        continue
                    seen_paths.add(real_path)
                    profiles.append({
                        "b": "Firefox", "p": sub.name,
                        "path": str(sub), "type": "F"
                    })
            except (PermissionError, OSError) as e:
                logger.debug(f"Firefox 标准路径枚举受限 [{ff_base}]: {e}")
        return profiles

    @staticmethod
    def _win_scan_shallow_nonstandard(drives: List[Path],
                                       seen_paths: Set[str]) -> List[Dict[str, str]]:
        """
        策略二：全盘符浅层非标准路径穿透扫描（深度 ≤ 3 层）。

        专为以下场景设计：
          · WTG (Windows To Go) 外置系统盘数据遗留
          · 用户手动将 User Data / Profile 重定向至 D 盘
          · 绿色便携版浏览器（Chrome Portable / Firefox Portable）
          · 第三方一键搬家工具生成的非标准路径

        深度 3 层可覆盖：
          D:\\User Data\\Default\\               ← 深度1进入，深度2命中
          D:\\Tools\\Chrome\\User Data\\Default  ← 深度1→2→3命中
        """
        profiles = []

        def _scan_dir(current: Path, depth: int):
            if depth > 3:
                return
            try:
                entries = list(current.iterdir())
            except (PermissionError, OSError):
                return

            for entry in entries:
                if not entry.is_dir():
                    continue
                name_lower = entry.name.lower()
                # 跳过纯系统噪音目录，用户数据目录（documents/downloads等）保留扫描
                if name_lower in ScannerCore._SKIP_DIRS or name_lower.startswith("$"):
                    continue

                # ── Firefox 外置便携版：通过 places.sqlite 特征识别单个 Profile 目录 ──
                if (entry / "places.sqlite").exists():
                    try:
                        real_path = str(entry.resolve())
                    except OSError:
                        real_path = str(entry)
                    if real_path not in seen_paths:
                        seen_paths.add(real_path)
                        profiles.append({
                            "b": "Firefox(外置)", "p": entry.name,
                            "path": str(entry), "type": "F"
                        })
                    # 已识别为 Firefox Profile，无需继续向内递归
                    continue

                # ── Chromium 系外置：通过 History 子目录特征识别 User Data 根 ──
                if ScannerCore._is_valid_user_data(entry):
                    # ✅ 使用独立方法推断浏览器名，内含完整异常保护
                    bname = ScannerCore._infer_browser_name(entry)
                    profiles.extend(
                        ScannerCore._collect_chrome_profiles(entry, bname, seen_paths)
                    )
                    # 已识别为 User Data 根，无需继续向内递归（避免重复计入子 Profile）
                    continue

                # 两种特征均未命中，继续向下递归搜索
                _scan_dir(entry, depth + 1)

        for drive in drives:
            _scan_dir(drive, 1)

        return profiles

    @staticmethod
    def _snapshot_database(db_path: Path, temp_dir: Path) -> Optional[Path]:
        if not db_path.exists():
            return None
        snap_name = f"audit_db_{time.time_ns()}.db"
        target_main_db = temp_dir / snap_name
        try:
            with open(db_path, "rb") as f_in:
                with open(target_main_db, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            return target_main_db
        except IOError as e:
            msg = str(e).lower()
            if "permission" in msg or "denied" in msg:
                if "safari" in str(db_path).lower():
                    gui_warning_queue.put(("warning",
                        f"【系统沙盒拦截】无法提取 Safari 数据库：\n{db_path.name}\n\n"
                        "解决办法：请前往「系统设置 -> 隐私与安全性 -> 完全磁盘访问权限」，允许本程序。"))
                logger.warning(f"【权限受限】{db_path.name} 拒绝访问。")
            else:
                logger.error(f"流式提取失败: {db_path.name} -> {e}")
            return None
        except Exception as e:
            logger.error(f"提取快照异常: {db_path.name} -> {e}")
            return None

    @staticmethod
    def get_profiles() -> List[Dict[str, str]]:
        profiles = []

        # ── Windows 全盘符主动智能穿透 ───────────────────────────────────────────
        if sys.platform == 'win32':
            seen_paths: Set[str] = set()
            username = ScannerCore._get_current_username()
            drives = ScannerCore._get_windows_drives()

            logger.info(f"[Win] 智能枚举盘符: {[str(d) for d in drives]}，当前取证用户映射: {username}")

            # 策略一：Chromium 系标准路径高速扫描
            std_profiles = ScannerCore._win_scan_standard_paths(drives, username, seen_paths)
            profiles.extend(std_profiles)
            logger.info(f"[Win] Chromium 标准路径命中 {len(std_profiles)} 个 Profile")

            # 策略一-B：Firefox 全盘符标准 Roaming 路径扫描
            ff_std_profiles = ScannerCore._win_scan_firefox_standard(drives, username, seen_paths)
            profiles.extend(ff_std_profiles)
            logger.info(f"[Win] Firefox 标准路径命中 {len(ff_std_profiles)} 个 Profile")

            # 策略二：浅层非标准路径穿透（WTG/D盘重定向/便携版全覆盖）
            ext_profiles = ScannerCore._win_scan_shallow_nonstandard(drives, seen_paths)
            profiles.extend(ext_profiles)
            logger.info(f"[Win] 非标准路径穿透命中 {len(ext_profiles)} 个 Profile")

            logger.info(f"[Win] 全盘扫描就绪：共锁定 {len(profiles)} 个独立浏览器配置分身")

        # ── macOS（精美保留原逻辑，零改动）────────────────────────────────────
        elif sys.platform == 'darwin':
            home = Path.home()
            safari_path = home / "Library/Safari"
            if (safari_path / "History.db").exists() or (safari_path / "Bookmarks.plist").exists():
                profiles.append({"b": "Safari", "p": "MainSystem", "path": str(safari_path), "type": "S"})
            
            mac_paths = {
                "Chrome": home / "Library/Application Support/Google/Chrome",
                "Edge": home / "Library/Application Support/Microsoft Edge",
                "Brave": home / "Library/Application Support/BraveSoftware/Brave-Browser",
                "Arc": home / "Library/Application Support/Arc/User Data"
            }
            for name, base in mac_paths.items():
                if not base.exists():
                    continue
                try:
                    for sub in base.iterdir():
                        if sub.is_dir() and (sub / "History").exists():
                            profiles.append({"b": name, "p": sub.name, "path": str(sub), "type": "C"})
                except Exception:
                    pass
            
            ff_mac = home / "Library/Application Support/Firefox/Profiles"
            if ff_mac.exists():
                try:
                    for sub in ff_mac.iterdir():
                        if sub.is_dir() and (sub / "places.sqlite").exists():
                            profiles.append({"b": "Firefox", "p": sub.name, "path": str(sub), "type": "F"})
                except Exception:
                    pass

        return profiles

    @staticmethod
    def scan(profile: Dict[str, str], rule_dict: Dict[str, str], temp_dir: Path) -> List[Tuple]:
        hits = []
        if profile["type"] == "C":
            profile_path = Path(profile["path"])
            db_path = profile_path / "History"
            tmp_db = ScannerCore._snapshot_database(db_path, temp_dir)
            if tmp_db:
                conn = None
                try:
                    conn = sqlite3.connect(f"file:{tmp_db}?mode=ro", uri=True, timeout=10)
                    cursor = conn.cursor()
                    cursor.execute("SELECT url FROM urls")
                    while True:
                        rows = cursor.fetchmany(5000)
                        if not rows: break
                        for (url,) in rows: ScannerCore._match(url, "历史记录", profile, rule_dict, hits)
                    
                    try:
                        cursor.execute("SELECT target_path, tab_url FROM downloads")
                        while True:
                            d_rows = cursor.fetchmany(5000)
                            if not d_rows: break
                            for path, url in d_rows: ScannerCore._match(url or path, "下载文件", profile, rule_dict, hits)
                    except sqlite3.OperationalError: 
                        try:
                            cursor.execute("SELECT target_path, url FROM downloads")
                            while True:
                                d_rows = cursor.fetchmany(5000)
                                if not d_rows: break
                                for path, url in d_rows: ScannerCore._match(url or path, "下载文件", profile, rule_dict, hits)
                        except sqlite3.OperationalError: pass
                        
                    try:
                        cursor.execute("SELECT url FROM downloads_url_chains")
                        while True:
                            c_rows = cursor.fetchmany(5000)
                            if not c_rows: break
                            for (url,) in c_rows: ScannerCore._match(url, "下载文件", profile, rule_dict, hits)
                    except sqlite3.OperationalError: pass
                except sqlite3.DatabaseError as e: logger.debug(f"Chrome系DB异常: {e}")
                finally:
                    if conn: conn.close()
                    if tmp_db:
                        try: tmp_db.unlink(missing_ok=True)
                        except: pass

            bk_path = profile_path / "Bookmarks"
            if bk_path.exists():
                try:
                    with open(bk_path, 'r', encoding='utf-8', errors='ignore') as f:
                        data = json.load(f)
                        def walk_chrome(node):
                            if "url" in node: ScannerCore._match(node["url"], "浏览器书签", profile, rule_dict, hits)
                            if "children" in node:
                                for child in node["children"]: walk_chrome(child)
                        if "roots" in data:
                            for key in ["bookmark_bar", "other", "synced"]:
                                if key in data["roots"]: walk_chrome(data["roots"][key])
                except Exception: pass

        elif profile["type"] == "F":
            profile_path = Path(profile["path"])
            db_path = profile_path / "places.sqlite"
            tmp_db = ScannerCore._snapshot_database(db_path, temp_dir)
            if tmp_db:
                conn = None
                try:
                    conn = sqlite3.connect(f"file:{tmp_db}?mode=ro", uri=True, timeout=10)
                    cursor = conn.cursor()
                    cursor.execute("SELECT url FROM moz_places")
                    while True:
                        rows = cursor.fetchmany(5000)
                        if not rows: break
                        for (url,) in rows: ScannerCore._match(url, "历史记录", profile, rule_dict, hits)
                    
                    try:
                        cursor.execute("""
                            SELECT DISTINCT mp.url FROM moz_annos ma
                            JOIN moz_places mp ON ma.place_id = mp.id
                            WHERE ma.anno_attribute_id IN (SELECT id FROM moz_anno_attributes WHERE name LIKE '%download%')
                            UNION
                            SELECT DISTINCT mp.url FROM moz_places mp
                            WHERE mp.url LIKE 'file://%' OR mp.url LIKE '%content-signature%'
                        """)
                        while True:
                            d_rows = cursor.fetchmany(5000)
                            if not d_rows: break
                            for (url,) in d_rows: ScannerCore._match(url, "下载文件", profile, rule_dict, hits)
                    except sqlite3.OperationalError: pass
                except sqlite3.DatabaseError as e: logger.debug(f"Firefox系DB异常: {e}")
                finally:
                    if conn: conn.close()
                    if tmp_db:
                        try: tmp_db.unlink(missing_ok=True)
                        except: pass

            dl_json_path = profile_path / "downloads.json"
            if dl_json_path.exists():
                try:
                    with open(dl_json_path, 'r', encoding='utf-8', errors='ignore') as f:
                        dl_data = json.load(f)
                        if isinstance(dl_data, list):
                            for item in dl_data:
                                if isinstance(item, dict) and "url" in item:
                                    ScannerCore._match(item["url"], "下载文件", profile, rule_dict, hits)
                except Exception: pass

        elif profile["type"] == "S":
            profile_path = Path(profile["path"])
            db_path = profile_path / "History.db"
            tmp_db = ScannerCore._snapshot_database(db_path, temp_dir)
            if tmp_db:
                conn = None
                try:
                    conn = sqlite3.connect(f"file:{tmp_db}?mode=ro", uri=True, timeout=10)
                    cursor = conn.cursor()
                    try: 
                        cursor.execute("SELECT DISTINCT history_items.url FROM history_items INNER JOIN history_visits ON history_items.id = history_visits.history_item")
                    except sqlite3.OperationalError: 
                        try: cursor.execute("SELECT url FROM history_items")
                        except sqlite3.OperationalError: pass
                        
                    while True:
                        rows = cursor.fetchmany(5000)
                        if not rows: break
                        for (url,) in rows: ScannerCore._match(url, "历史记录", profile, rule_dict, hits)
                except sqlite3.DatabaseError as e: logger.debug(f"Safari DB异常: {e}")
                finally:
                    if conn: conn.close()
                    if tmp_db:
                        try: tmp_db.unlink(missing_ok=True)
                        except: pass

            plist_path = profile_path / "Bookmarks.plist"
            if plist_path.exists():
                try:
                    with open(plist_path, 'rb') as f:
                        plist_data = plistlib.load(f)
                        def walk_safari(node):
                            if isinstance(node, dict):
                                if "URLString" in node: ScannerCore._match(node["URLString"], "浏览器书签", profile, rule_dict, hits)
                                for v in node.values(): walk_safari(v)
                            elif isinstance(node, list):
                                for item in node: walk_safari(item)
                        walk_safari(plist_data)
                except Exception as e: logger.debug(f"Safari Plist解析异常: {e}")
                    
        return hits

    @staticmethod
    def _match(url: str, info_type: str, profile: Dict, rule_dict: Dict, hits: List):
        if not url: return
        try:
            domain = urlparse(url).netloc.lower() if url.startswith('http') else url.lower()
            if ":" in domain: domain = domain.split(":")[0]
            parts = domain.split('.')
            for i in range(len(parts)):
                if ".".join(parts[i:]) in ScannerCore.GLOBAL_WHITE_SET: return 
            for i in range(len(parts)):
                sub_domain = ".".join(parts[i:])
                if "." in sub_domain and sub_domain in rule_dict:
                    hits.append((profile["b"], profile["p"], info_type, rule_dict[sub_domain], url))
                    return 
        except Exception:
            pass

# =================================================
# 3. GUI 控制台 (无痕高稳定性重隔绝正式发布版)
# =================================================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("浏览器痕迹分析 v1.1.6")
        
        if sys.platform == 'win32':
            self.geometry("460x210")
        else:
            self.geometry("460x170")
            
        self.resizable(False, False)
        
        self.all_hits = []
        self.is_scanning = False 
        self.generated_reports = []  # 🔒 统一生命周期锁：用于最终强力物理蒸发
        
        ResourceManager.initialize()
        self.protocol("WM_DELETE_WINDOW", self.on_exit)
        self.queue = queue.Queue()
        self.core_temp_dir = Path(tempfile.mkdtemp(prefix="audit_core_"))
        
        self._build_ui()
        self.after(100, self._process_queue)

    def _build_ui(self):
        header = tk.Frame(self, pady=10)
        header.pack(fill=tk.X, padx=15)
        title_box = tk.Frame(header)
        title_box.pack(side=tk.LEFT)
        tk.Label(title_box, text="TRACE AUDITOR PRO", font=("Arial", 8, "bold"), fg="#ff4d4f").pack(anchor="w")
        tk.Label(title_box, text="浏览器痕迹分析", font=("Arial", 14, "bold")).pack(anchor="w")

        btn_box = tk.Frame(self)
        btn_box.pack(fill=tk.X, padx=15, pady=5)
        self.btn_run = tk.Button(btn_box, text="🚀 开始检测", command=self.pre_run_check, font=("Arial", 10, "bold"), height=2)
        self.btn_run.pack(fill=tk.X, expand=True)

        self.pbar = ttk.Progressbar(self, mode='determinate')
        self.pbar.pack(fill=tk.X, padx=15, pady=(10, 0))
        self.status_lbl = tk.Label(self, text="系统就绪，全盘智能审计通道已就绪...", fg="#666", font=("Arial", 9))
        self.status_lbl.pack(padx=15, anchor="w", pady=5)

    def pre_run_check(self):
        self.run()

    def run(self):
        self.btn_run.config(state="disabled")
        self.all_hits.clear()
        self.is_scanning = True
        rules = ResourceManager.load_audit_rules()

        def task():
            try:
                profiles = ScannerCore.get_profiles()
                if not profiles:
                    self.queue.put(("msg", "分析结束：未定位到有效的浏览器历史配置文件。"))
                    self.queue.put(("done", []))
                    return

                final_results = []
                for i, p in enumerate(profiles):
                    if not self.is_scanning: break 
                    self.queue.put(("msg", f"正在深度检索: {p['b']} -> {p['p']}"))
                    hits = ScannerCore.scan(p, rules, self.core_temp_dir)
                    final_results.extend(hits)
                    self.queue.put(("progress", int((i+1)/len(profiles)*100)))
                    
                if self.is_scanning:
                    self.queue.put(("done", final_results))
            except Exception as e:
                logger.error("扫描核心异常", exc_info=True)
                self.queue.put(("msg", f"异常中断: {str(e)}"))
                self.queue.put(("error", None))
            finally:
                self.is_scanning = False

        threading.Thread(target=task, daemon=True).start()

    def execute_instant_report(self):
        if not self.all_hits: return

        report_dir = Path(tempfile.gettempdir())
        file_name = f"Browser_Audit_Report_{time.time_ns()}.html"
        target_path = report_dir / file_name
        
        unique_hits = []
        seen = set()
        for h in self.all_hits:
            key = (h[0], h[1], h[2], h[4]) 
            if key not in seen:
                seen.add(key)
                unique_hits.append(h)
                
        total_count = len(unique_hits)
        
        html_content = [
            '<!DOCTYPE html><html><head><meta charset="utf-8"><title>浏览器痕迹取证分析报告</title>',
            '<style>body{font-family:"Segoe UI",Arial,sans-serif;margin:0;padding:25px;background-color:#f5f7fa;}'
            '.container{max-width:1500px;margin:auto;background:#fff;padding:30px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.06);}'
            'h1{color:#2c3e50;text-align:center;border-bottom:2px solid #1890ff;padding-bottom:15px;margin-top:0;font-size:24px;}'
            '.summary{font-size:14px;color:#555;margin-bottom:20px;display:flex;justify-content:space-between;'
            'background:#e6f7ff;padding:12px 20px;border-radius:4px;border-left:4px solid #1890ff;}'
            '.highlight{color:#ff4d4f;font-weight:bold;font-size:16px;}'
            'table{width:100%;border-collapse:collapse;table-layout:fixed;box-shadow:0 1px 3px rgba(0,0,0,0.02);}'
            'th:nth-child(1),td:nth-child(1){width:10%;text-align:center;}'
            'th:nth-child(2),td:nth-child(2){width:12%;text-align:center;}'
            'th:nth-child(3),td:nth-child(3){width:10%;text-align:center;}'
            'th:nth-child(4),td:nth-child(4){width:13%;text-align:center;}'
            'th:nth-child(5),td:nth-child(5){width:55%;}'
            'th,td{padding:12px;border-bottom:1px solid #f0f0f0;font-size:13px;word-wrap:break-word;}'
            'th{background-color:#1890ff;color:white;font-weight:600;text-align:center;}'
            'tr:hover{background-color:#fafafa;}'
            '.url-cell{color:#2c3e50;font-family:"Consolas",monospace;user-select:all;'
            'background-color:#fafafa;padding:6px 10px;border-radius:4px;border:1px solid #e8e8e8;}'
            '</style>',
            '</head><body><div class="container"><h1>🔍 浏览器痕迹审计分析报告 (v1.1.6)</h1>',
            f'<div class="summary"><span>生成时间：{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</span>'
            f'<span>共计发现留痕记录：<span class="highlight">{total_count}</span> 条</span></div>',
            '<table><tr><th>浏览器</th><th>配置分身</th><th>记录类型</th><th>审计分类</th><th>详细地址（双击可全选复制）</th></tr>'
        ]
        
        for h in unique_hits:
            raw_url = h[4]
            safe_url = html.escape(raw_url, quote=True)
            html_content.append(
                f"<tr><td>{html.escape(h[0])}</td><td>{html.escape(h[1])}</td>"
                f"<td>{html.escape(h[2])}</td><td><strong>{html.escape(h[3])}</strong></td>"
                f"<td><div class='url-cell' title='{safe_url}'>{safe_url}</div></td></tr>"
            )
            
        html_content.append("</table></div></body></html>")
        
        try:
            with open(target_path, "w", encoding="utf-8") as f: 
                f.write("".join(html_content))
            if sys.platform == "darwin":
                subprocess.Popen(["open", str(target_path)])
            else:
                webbrowser.open(target_path.as_uri())
            self.generated_reports.append(target_path)
        except Exception as e:
            logger.error(f"无痕生成调用流异常: {e}")

    def _process_queue(self):
        try:
            while not gui_warning_queue.empty():
                w_type, w_msg = gui_warning_queue.get_nowait()
                if w_type == "warning":
                    messagebox.showwarning("系统权限受限提示", w_msg)

            while not self.queue.empty():
                msg, val = self.queue.get_nowait()
                if msg == "progress": 
                    self.pbar["value"] = val
                elif msg == "msg": 
                    self.status_lbl.config(text=val)
                elif msg == "done":
                    self.btn_run.config(state="normal")
                    self.all_hits = val
                    if self.all_hits:
                        self.execute_instant_report()
                        self.status_lbl.config(text="完成！分析结果已无痕渲染（退出窗口将自动粉碎报告）。")
                    else:
                        self.status_lbl.config(text="扫描完成：未发现符合规则的留痕。")
                        messagebox.showinfo("检测结果", "未检测到任何匹配的交互历史。")
                elif msg == "error":
                    self.btn_run.config(state="normal")
        finally:
            try: self.update_idletasks()
            except Exception: pass
            self.after(100, self._process_queue)

    def on_exit(self):
        self.is_scanning = False 
        if hasattr(self, 'generated_reports'):
            for report_path in self.generated_reports:
                try:
                    if report_path.exists():
                        report_path.unlink()
                except Exception:
                    pass
        try: shutil.rmtree(self.core_temp_dir, ignore_errors=True)
        except Exception: pass
        self.destroy()

if __name__ == "__main__":
    app = App()
    app.mainloop()
