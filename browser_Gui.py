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
from typing import List, Dict, Tuple, Optional

# =================================================
# 0. 全局配置与高级日志配置
# =================================================
CACHE_VERSION = 9

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

def get_base_directory() -> Path:
    # 1. 如果是打包后的运行环境
    if getattr(sys, 'frozen', False):
        exec_dir = Path(sys.executable).parent # 对应 macOS 内部的 Contents/MacOS
        
        # 【最高优先级】：如果用户把 custom-domains.conf 放在了二进制程序 BrowserAudit 同级目录下
        if (exec_dir / "custom-domains.conf").exists():
            return exec_dir
            
        # 【次高优先级】：如果用户把 custom-domains.conf 放在了 浏览器痕迹分析.app 的外部同级目录下
        if sys.platform == 'darwin' and exec_dir.name == "MacOS" and exec_dir.parent.name == "Contents":
            app_bundle_parent = exec_dir.parent.parent.parent
            if (app_bundle_parent / "custom-domains.conf").exists():
                return app_bundle_parent
                
        # 【第三顺位】：检查当前工作目录
        if (Path.cwd() / "custom-domains.conf").exists():
            return Path.cwd()
            
        # 默认绝对兜底：未找到时默认以 .app 的外层同级目录作为基准（用于自动初始化生成文件）
        if sys.platform == 'darwin' and exec_dir.name == "MacOS" and exec_dir.parent.name == "Contents":
            return exec_dir.parent.parent.parent
        return exec_dir
        
    # 2. 如果是源码直接调试运行 (python3 browser_Gui.py)
    script_dir = Path(__file__).resolve().parent
    if (script_dir / "custom-domains.conf").exists():
        return script_dir
    return Path.cwd()

BASE_DIR = get_base_directory()
CUSTOM_FILE = BASE_DIR / "custom-domains.conf"
CACHE_FILE = BASE_DIR / "rules.cache.json"

class ResourceManager:
    @staticmethod
    def initialize():
        if not CUSTOM_FILE.exists():
            try:
                CUSTOM_FILE.write_text(
                    "# 专项规则库 (自定义扩展)\n"
                    "heygen.com=AI视频(HeyGen)\n"
                    "hailuoai.com=AI服务(海螺AI)\n"
                    "mailum.com=未知安全邮箱\n"
                    "tongyi.aliyun.com=AI服务(阿里通义)\n"
                    "doubao.com=AI服务(字节豆包)\n"
                    "yuanbao.tencent.com=AI服务(腾讯元宝)\n"
                    "yiyan.baidu.com=AI服务(文心一言)\n"
                    "tiangong.cn=AI服务(昆仑天工)\n"
                    "kimi.ai=AI服务(月暗Kimi)\n"
                    "deepseek.com=AI服务(DeepSeek)\n"
                    "chatglm.cn=AI服务(智谱清言)\n"
                    "baichuan-ai.com=AI服务(百川智能)\n"
                    "minimax.chat=AI服务(MiniMax星野)\n"
                    "klingai.com=AI视频(快手可灵)\n"
                    "viggle.ai=AI视频(Viggle动画)\n"
                    "shengxiang.baidu.com=AI视频(百度生息)\n"
                    "server=/dreamina.capcut.com/114.114.114.114\n",
                    encoding="utf-8"
                )
            except IOError as e:
                logger.error(f"规则库初始化失败: {e}")

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
        if CACHE_FILE.exists() and CUSTOM_FILE.exists():
            if CACHE_FILE.stat().st_mtime > CUSTOM_FILE.stat().st_mtime:
                try:
                    with open(CACHE_FILE, "r", encoding="utf-8") as f:
                        cache_data = json.load(f)
                        if isinstance(cache_data, dict) and cache_data.get("version") == CACHE_VERSION:
                            rules = cache_data.get("rules", {})
                except Exception:
                    rules = {}

        if not rules and CUSTOM_FILE.exists():
            try:
                server_pattern = re.compile(r"^server=/([^/]+)/")
                with open(CUSTOM_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
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
                if rules:
                    with open(CACHE_FILE, "w", encoding="utf-8") as f:
                        json.dump({"version": CACHE_VERSION, "rules": rules}, f, ensure_ascii=False)
            except Exception as e:
                logger.error(f"编译规则库失败: {e}")
        return rules

# =================================================
# 2. 扫描内核
# =================================================
class ScannerCore:
    GLOBAL_WHITE_SET = frozenset({
        "google.com", "google.com.hk", "gstatic.com", "googleapis.com", 
        "apple.com", "icloud.com", "microsoft.com", "bing.com", "msn.com"
    })

    @staticmethod
    def _snapshot_database(db_path: Path, temp_dir: Path) -> Optional[Path]:
        if not db_path.exists(): return None
        snap_name = f"audit_db_{time.time_ns()}.db"
        target_main_db = temp_dir / snap_name
        
        try:
            with open(db_path, "rb") as f_in:
                with open(target_main_db, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            return target_main_db
        except Exception as e:
            logger.debug(f"提取快照静默忽略: {db_path.name} -> {e}")
            return None

    @staticmethod
    def get_profiles() -> List[Dict[str, str]]:
        profiles = []
        if sys.platform == 'win32':
            local, appdata = os.getenv('LOCALAPPDATA', ''), os.getenv('APPDATA', '')
            if local:
                c_browsers = {
                    "Chrome": Path(local) / "Google" / "Chrome" / "User Data",
                    "Edge": Path(local) / "Microsoft" / "Edge" / "User Data",
                    "Brave": Path(local) / "BraveSoftware" / "Brave-Browser" / "User Data",
                    "360极速X": Path(local) / "360chromeX" / "Chrome" / "User Data",
                    "Arc": Path(local) / "Packages" / "TheBrowserCompany.Arc_tchbfspa9nw8p" / "LocalCache" / "Local" / "Arc" / "User Data"
                }
                for name, base in c_browsers.items():
                    if not base.exists(): continue
                    try:
                        for sub in base.iterdir():
                            if sub.is_dir() and (sub / "History").exists():
                                profiles.append({"b": name, "p": sub.name, "path": str(sub), "type": "C"})
                    except Exception: pass
            
            if appdata:
                ff_base = Path(appdata) / "Mozilla" / "Firefox" / "Profiles"
                if ff_base.exists():
                    try:
                        for sub in ff_base.iterdir():
                            if sub.is_dir() and (sub / "places.sqlite").exists():
                                profiles.append({"b": "Firefox", "p": sub.name, "path": str(sub), "type": "F"})
                    except Exception: pass

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
                if not base.exists(): continue
                try:
                    for sub in base.iterdir():
                        if sub.is_dir() and (sub / "History").exists():
                            profiles.append({"b": name, "p": sub.name, "path": str(sub), "type": "C"})
                    except Exception: pass
            
            ff_mac = home / "Library/Application Support/Firefox/Profiles"
            if ff_mac.exists():
                try:
                    for sub in ff_mac.iterdir():
                        if sub.is_dir() and (sub / "places.sqlite").exists():
                            profiles.append({"b": "Firefox", "p": sub.name, "path": str(sub), "type": "F"})
                except Exception: pass
                
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
                    
                except sqlite3.DatabaseError: pass
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
                except sqlite3.DatabaseError: pass
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
                        try:
                            rows = cursor.fetchmany(5000)
                            if not rows: break
                            for (url,) in rows: ScannerCore._match(url, "历史记录", profile, rule_dict, hits)
                        except Exception: break
                except sqlite3.DatabaseError: pass
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
                except Exception: pass
                    
        return hits

    @staticmethod
    def _match(url: str, info_type: str, profile: Dict, rule_dict: Dict, hits: List):
        if not url: return
        try:
            domain = urlparse(url).netloc.lower() if url.startswith('http') else url.lower()
            if ":" in domain: domain = domain.split(":")[0]
            
            parts = domain.split('.')
            for i in range(len(parts)):
                if ".".join(parts[i:]) in ScannerCore.GLOBAL_WHITE_SET:
                    return 

            for i in range(len(parts)):
                sub_domain = ".".join(parts[i:])
                if "." in sub_domain and sub_domain in rule_dict:
                    hits.append((profile["b"], profile["p"], info_type, rule_dict[sub_domain], url))
                    return 
        except Exception:
            pass

# =================================================
# 3. GUI 控制台
# =================================================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("浏览器痕迹分析") 
        self.geometry("460x220")
        self.resizable(False, False)
        
        self.all_hits = []
        self.current_report_path = None
        self.is_scanning = False 
        
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
        tk.Label(title_box, text="TRACE ANALYZER", font=("Arial", 8, "bold"), fg="#ff4d4f").pack(anchor="w")
        tk.Label(title_box, text="浏览器痕迹分析", font=("Arial", 14, "bold")).pack(anchor="w")

        btn_box = tk.Frame(self)
        btn_box.pack(fill=tk.X, padx=15, pady=5)
        self.btn_run = tk.Button(btn_box, text="🚀 开始检测", command=self.pre_run_check, font=("Arial", 10, "bold"), height=2)
        self.btn_run.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.btn_export = tk.Button(btn_box, text="打开网页结果", command=self.open_current_html, font=("Arial", 10), height=2, state="disabled")
        self.btn_export.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(5, 0))

        self.pbar = ttk.Progressbar(self, mode='determinate')
        self.pbar.pack(fill=tk.X, padx=15, pady=(10, 0))
        self.status_lbl = tk.Label(self, text="系统就绪，等待运行...", fg="#666", font=("Arial", 9))
        self.status_lbl.pack(padx=15, anchor="w", pady=5)

    def pre_run_check(self):
        running = ResourceManager.is_browser_running()
        if running:
            browsers = ", ".join(running).title()
            if not messagebox.askokcancel("提取提示", f"检测到 {browsers} 正在运行。\n系统将采用热备方案安全提取，是否继续？"): return
        self.run()

    def run(self):
        self.btn_run.config(state="disabled")
        self.btn_export.config(state="disabled")
        self.all_hits.clear()
        self.is_scanning = True
        
        rules = ResourceManager.load_audit_rules()
        if not rules:
            messagebox.showwarning("警告", "规则库为空或加载失败，请检查配置。")
            self.btn_run.config(state="normal")
            self.is_scanning = False
            return

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
                    
                    self.queue.put(("msg", f"正在检索: {p['b']} -> {p['p']}"))
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

    def generate_html_file(self) -> Optional[str]:
        report_dir = BASE_DIR
        if not os.access(report_dir, os.W_OK):
            report_dir = Path(tempfile.gettempdir())
        
        file_name = f"Browser_Audit_Report_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.html"
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
            '<!DOCTYPE html><html><head><meta charset="utf-8"><title>浏览器痕迹 analysis 报告</title>',
            '<style>body{font-family:"Segoe UI",Arial,sans-serif;margin:0;padding:25px;background-color:#f5f7fa;}.container{max-width:1500px;margin:auto;background:#fff;padding:30px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.06);}h1{color:#2c3e50;text-align:center;border-bottom:2px solid #1890ff;padding-bottom:15px;margin-top:0;font-size:24px;}.summary{font-size:14px;color:#555;margin-bottom:20px;display:flex;justify-content:space-between;background:#e6f7ff;padding:12px 20px;border-radius:4px;border-left:4px solid #1890ff;}.highlight{color:#ff4d4f;font-weight:bold;font-size:16px;}table{width:100%;border-collapse:collapse;table-layout:fixed;box-shadow:0 1px 3px rgba(0,0,0,0.02);}th:nth-child(1),td:nth-child(1){width:10%;text-align:center;}th:nth-child(2),td:nth-child(2){width:12%;text-align:center;}th:nth-child(3),td:nth-child(3){width:10%;text-align:center;}th:nth-child(4),td:nth-child(4){width:13%;text-align:center;}th:nth-child(5),td:nth-child(5){width:55%;}th,td{padding:0 12px;height:38px;line-height:38px;border-bottom:1px solid #f0f0f0;font-size:13px;}th{background-color:#1890ff;color:white;font-weight:600;}tr:hover{background-color:#fafafa;}.url-cell{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}a{color:#1890ff;text-decoration:none;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}a:hover{color:#40a9ff;text-decoration:underline;}</style>',
            '</head><body><div class="container"><h1>🔍 浏览器痕迹分析报告</h1>',
            f'<div class="summary"><span>生成时间：{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</span><span>共计发现留痕记录：<span class="highlight">{total_count}</span> 条</span></div>',
            '<table><tr><th>浏览器</th><th>配置分身</th><th>记录类型</th><th>审计分类</th><th>详细地址</th></tr>'
        ]
        
        for h in unique_hits:
            raw_url = h[4]
            safe_url = html.escape(raw_url, quote=True)
            clean_href = safe_url if raw_url.strip().lower().startswith(("http://", "https://")) else "#"

            html_content.append(
                f"<tr><td>{html.escape(h[0])}</td><td>{html.escape(h[1])}</td>"
                f"<td>{html.escape(h[2])}</td><td><strong>{html.escape(h[3])}</strong></td>"
                f"<td class='url-cell'><a href='{clean_href}' target='_blank' title='{safe_url}'>{safe_url}</a></td></tr>"
            )
            
        html_content.append("</table></div></body></html>")
        
        try:
            with open(target_path, "w", encoding="utf-8") as f: 
                f.write("".join(html_content))
            return str(target_path)
        except Exception as e:
            logger.error(f"HTML报告文件生成失败: {e}")
            return None

    def open_current_html(self):
        if self.current_report_path and os.path.exists(self.current_report_path):
            try:
                if sys.platform == "darwin":
                    subprocess.Popen(["open", str(self.current_report_path)])
                else:
                    uri = Path(self.current_report_path).as_uri()
                    webbrowser.open(uri)
            except Exception as e:
                logger.error(f"打开报告文件异常: {e}")

    def _process_queue(self):
        try:
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
                        self.current_report_path = self.generate_html_file()
                        if self.current_report_path:
                            self.status_lbl.config(text="完成！报告已成功输出。")
                            self.btn_export.config(state="normal")
                            self.after(300, self.open_current_html)
                        else:
                            self.status_lbl.config(text="报告生成失败，请检查读写权限。")
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
        try: shutil.rmtree(self.core_temp_dir, ignore_errors=True)
        except Exception: pass
        self.destroy()

if __name__ == "__main__":
    app = App()
    app.mainloop()