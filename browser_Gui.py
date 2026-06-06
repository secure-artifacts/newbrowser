import os
import sys
import time
import json
import re
import shutil
import sqlite3
import threading
import queue
import tempfile
import webbrowser  
from datetime import datetime
from urllib.parse import urlparse
import tkinter as tk
from tkinter import ttk, messagebox

# =================================================
# 1. 全平台绝对路径自适应锚定核心 (v1.1.0 工业级闭环)
# =================================================
if getattr(sys, 'frozen', False):
    if sys.platform == 'darwin':
        # Mac 打包环境下，精准向外退 4 层到 .app 外面的用户真实目录
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(sys.executable))))
    else:
        # Windows 打包环境下，直接获取 .exe 所在目录
        BASE_DIR = os.path.dirname(sys.executable)
else:
    # 开发调试环境下，获取当前 .py 脚本所在目录
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 全局强绑定绝对路径，彻底免疫系统级当前目录（CWD）丢失带来的盲区
CUSTOM_FILE = os.path.join(BASE_DIR, "custom-domains.conf")

TEMP_DIR = tempfile.gettempdir()
HTML_REPORT_PATH = os.path.join(TEMP_DIR, "browser_audit_report.html")

class ResourceManager:
    @staticmethod
    def initialize():
        if os.path.exists(HTML_REPORT_PATH):
            try: os.remove(HTML_REPORT_PATH)
            except: pass

        if not os.path.exists(CUSTOM_FILE):
            try:
                with open(CUSTOM_FILE, "w", encoding="utf-8") as f:
                    f.write("# 专项审计规则库 (自定义扩展)\n")
                    f.write("# 支持格式1：域名=分类名称\n")
                    f.write("# 支持格式2：server=/域名/114.114.114.114\n\n")
                    f.write("heygen.com=AI视频(HeyGen)\n")
                    f.write("hailuoai.com=AI服务(海螺AI)\n")
                    f.write("server=/dreamina.capcut.com/114.114.114.114\n")
            except: pass

    @staticmethod
    def cleanup():
        if os.path.exists(HTML_REPORT_PATH):
            try: os.remove(HTML_REPORT_PATH)
            except: pass

    @staticmethod
    def is_browser_running():
        browsers = ["chrome.exe", "msedge.exe", "brave.exe", "360se.exe", "360chrome.exe", "firefox.exe", "chrome", "msedge", "brave", "firefox", "safari"]
        try:
            cmd = 'tasklist' if os.name == 'nt' else 'ps aux'
            tasks = os.popen(cmd).read().lower()
            return [b for b in browsers if b in tasks]
        except: return []

    @staticmethod
    def load_china_audit_rules():
        # 核心内置大厂规则
        china_heavy_domains = [
            "baidu.com", "qq.com", "taobao.com", "jd.com", "alipay.com", "weibo.com", 
            "bilibili.com", "zhihu.com", "douyin.com", "toutiao.com", "meituan.com",
            "163.com", "sina.com.cn", "sohu.com", "csdn.net", "gitee.com", "douban.com",
            "xiaohongshu.com", "kuaishou.com", "tencent.com", "alibaba.com", "net-cn.com",
            "txstatic.com", "alicdn.com", "bdstatic.com", "gtimg.com", "qpic.cn", 
            "tbcache.com", "pstatp.com", "amap.com", "volces.com", "qcloud.com",
            "360.cn", "360safe.com", "360se.com", "xunlei.com", "sandai.net", 
            "baiducontent.com", "baifubao.com", "myqcloud.com", "weiyun.com"
        ]
        rules = {domain: "中国大陆常见域名/服务" for domain in china_heavy_domains}
        
        if os.path.exists(CUSTOM_FILE):
            try:
                with open(CUSTOM_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        
                        # 自动识别解析 server=/domain/IP 路由器规则格式
                        if line.startswith("server="):
                            match = re.match(r"^server=/([^/]+)/", line)
                            if match:
                                domain = match.group(1).strip().lower()
                                if len(domain) < 4 or "." not in domain:
                                    continue
                                rules[domain] = "专项审计目标"
                                continue
                        
                        # 标准 域名=分类 格式
                        if "=" in line:
                            parts = line.split("=", 1)
                            domain = parts[0].strip().lower()
                            if len(domain) < 4 or "." not in domain:
                                continue
                            rules[domain] = parts[1].strip()
            except: pass
        return rules

# =================================================
# 2. 扫描内核：五合一高穿透双栖核心 (终极后缀匹配引擎)
# =================================================
class ScannerCore:
    GLOBAL_WHITE_LIST = [
        "google.com", "google.com.hk", "gstatic.com", "googleapis.com", 
        "googleusercontent.com", "g.co", "ggpht.com", 
        "apple.com", "icloud.com", "microsoft.com", "microsoft365.com",
        "windows.com", "live.com", "bing.com", "office.com", "msn.com"
    ]

    @staticmethod
    def get_profiles():
        profiles = []
        if os.name == 'nt':
            local = os.getenv('LOCALAPPDATA', '')
            appdata = os.getenv('APPDATA', '')
            if not local: return []
            c_browsers = {
                "Chrome": r"Google\Chrome\User Data",
                "Edge": r"Microsoft\Edge\User Data",
                "Brave": r"BraveSoftware\Brave-Browser\User Data"
            }
            for name, sub in c_browsers.items():
                base = os.path.join(local, sub)
                if not os.path.exists(base): continue
                try:
                    for item in os.listdir(base):
                        p = os.path.join(base, item)
                        if os.path.exists(os.path.join(p, "History")):
                            profiles.append({"b": name, "p": item, "path": p, "type": "C"})
                except: pass
            ff_base = os.path.join(appdata, r"Mozilla\Firefox\Profiles")
            if os.path.exists(ff_base):
                try:
                    for item in os.listdir(ff_base):
                        p = os.path.join(ff_base, item)
                        if os.path.exists(os.path.join(p, "places.sqlite")):
                            profiles.append({"b": "Firefox", "p": item, "path": p, "type": "F"})
                except: pass
        else:
            home = os.path.expanduser("~")
            safari_path = os.path.join(home, "Library/Safari")
            if os.path.exists(os.path.join(safari_path, "History.db")):
                profiles.append({"b": "Safari", "p": "MainSystem", "path": safari_path, "type": "S"})

            mac_paths = {
                "Chrome": os.path.join(home, "Library/Application Support/Google/Chrome"),
                "Edge": os.path.join(home, "Library/Application Support/Microsoft Edge"),
                "Brave": os.path.join(home, "Library/Application Support/BraveSoftware/Brave-Browser")
            }
            for name, base in mac_paths.items():
                if not os.path.exists(base): continue
                try:
                    if os.path.exists(os.path.join(base, "History")):
                        profiles.append({"b": name, "p": "MainProfile", "path": base, "type": "C"})
                    for item in os.listdir(base):
                        p = os.path.join(base, item)
                        if os.path.exists(os.path.join(p, "History")):
                            profiles.append({"b": name, "p": item, "path": p, "type": "C"})
                except: pass
            ff_mac = os.path.join(home, "Library/Application Support/Firefox/Profiles")
            if os.path.exists(ff_mac):
                try:
                    for item in os.listdir(ff_mac):
                        p = os.path.join(ff_mac, item)
                        if os.path.exists(os.path.join(p, "places.sqlite")):
                            profiles.append({"b": "Firefox", "p": item, "path": p, "type": "F"})
                except: pass
        return profiles

    @staticmethod
    def scan(profile, rule_dict):
        hits = []
        targets = list(rule_dict.keys())
        
        if profile["type"] == "C": db_name = "History"
        elif profile["type"] == "F": db_name = "places.sqlite"
        else: db_name = "History.db"
            
        db_path = os.path.join(profile["path"], db_name)
        if not os.path.exists(db_path): return []
        
        tmp_db = os.path.join(TEMP_DIR, f"sc_audit_snap_{int(time.time()*1000)}.db")
        try:
            with open(db_path, 'rb') as f_in:
                with open(tmp_db, 'wb') as f_out:
                    f_out.write(f_in.read())
            
            conn = sqlite3.connect(tmp_db)
            cursor = conn.cursor()
            
            if profile["type"] == "C": sql_hist = "SELECT url FROM urls"
            elif profile["type"] == "F": sql_hist = "SELECT url FROM moz_places"
            else: sql_hist = "SELECT url FROM history_items"
                
            cursor.execute(sql_hist)
            for (url,) in cursor.fetchall():
                ScannerCore._match(url, "历史记录", profile, rule_dict, targets, hits)

            if profile["type"] == "C":
                try:
                    cursor.execute("SELECT target_path, tab_url FROM downloads")
                    for path, url in cursor.fetchall():
                        ScannerCore._match(url or path, "下载文件", profile, rule_dict, targets, hits)
                except: pass
            conn.close()
        except Exception:
            if profile["type"] == "S":
                hits.append(("Safari", "安全拦截", "系统阻断", "请在Mac隐私设置中授予终端'完全磁盘访问权限'", ""))
        finally:
            if os.path.exists(tmp_db):
                try: os.remove(tmp_db)
                except: pass

        if profile["type"] == "C":
            bk_path = os.path.join(profile["path"], "Bookmarks")
            if os.path.exists(bk_path):
                try:
                    with open(bk_path, 'r', encoding='utf-8', errors='ignore') as f:
                        data = json.load(f)
                        def walk(node):
                            if "url" in node: ScannerCore._match(node["url"], "浏览器书签", profile, rule_dict, targets, hits)
                            if "children" in node:
                                for child in node["children"]: walk(child)
                        if "roots" in data:
                            for key in ["bookmark_bar", "other", "synced"]:
                                if key in data["roots"]: walk(data["roots"][key])
                except: pass
        return list(set(hits))

    @staticmethod
    def _match(url, info_type, profile, rule_dict, targets, hits):
        if not url: return
        try:
            domain = urlparse(url).netloc.lower() if url.startswith('http') else url.lower()
            if ":" in domain:
                domain = domain.split(":")[0]
            
            is_white = False
            for w in ScannerCore.GLOBAL_WHITE_LIST:
                if domain == w or domain.endswith('.' + w):
                    is_white = True
                    break
            if is_white: return
                
            for t in targets:
                if domain == t or domain.endswith('.' + t):
                    hits.append((profile["b"], profile["p"], info_type, rule_dict[t], url))
                    break
        except: pass

# =================================================
# 3. 精致控制台 GUI (自适应高级事件流驱动)
# =================================================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("浏览器痕迹分析") 
        self.geometry("450x200")
        self.resizable(False, False)
        self.configure(bg="#ffffff")
        
        self.all_hits_data = []
        ResourceManager.initialize()
        self.protocol("WM_DELETE_WINDOW", self.on_exit)
        self.queue = queue.Queue()
        self._build_ui()
        self.after(100, self._process_queue)

    def _build_ui(self):
        header = tk.Frame(self, bg="#ffffff", pady=10)
        header.pack(fill=tk.X, padx=15)
        
        title_box = tk.Frame(header, bg="#ffffff")
        title_box.pack(side=tk.LEFT)
        tk.Label(title_box, text="BROWSER TRACE ANALYZER", font=("Arial", 8, "bold"), fg="#ff4d4f", bg="#ffffff").pack(anchor="w")
        tk.Label(title_box, text="浏览器痕迹分析", font=("Arial", 14, "bold"), bg="#ffffff").pack(anchor="w")

        btn_box = tk.Frame(self, bg="#ffffff")
        btn_box.pack(fill=tk.X, padx=15, pady=5)
        self.btn_run = tk.Button(btn_box, text="🚀 开始检测", command=self.pre_run_check, font=("Arial", 10, "bold"), height=2)
        self.btn_run.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.btn_export = tk.Button(btn_box, text="打开网页结果", command=self.open_current_html, font=("Arial", 10), height=2, state="disabled")
        self.btn_export.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(5, 0))

        self.pbar = ttk.Progressbar(self, mode='determinate')
        self.pbar.pack(fill=tk.X, padx=15, pady=(15, 0))
        
        self.status_lbl = tk.Label(self, text="系统就绪，等待审计指令...", fg="#666", font=("Arial", 9), bg="#ffffff")
        self.status_lbl.pack(padx=15, anchor="w", pady=5)

    def pre_run_check(self):
        running = ResourceManager.is_browser_running()
        if running:
            if not messagebox.askokcancel("检测提示", "检测到浏览器实例正在后台流转，是否继续强行快照穿透？"): return
        self.run()

    def run(self):
        rules = ResourceManager.load_china_audit_rules()
        self.btn_run.config(state="disabled")
        self.btn_export.config(state="disabled")
        self.all_hits_data.clear()
        
        def task():
            try:
                profiles = ScannerCore.get_profiles()
                if not profiles:
                    self.queue.put(("msg", "检测结束：未定位到支持的配置路径。"))
                    self.queue.put(("done", "EMPTY_PATH"))
                    return

                for i, p in enumerate(profiles):
                    self.queue.put(("msg", f"正在穿透: {p['b']} -> {p['p']}"))
                    hits = ScannerCore.scan(p, rules)
                    if hits: self.queue.put(("data", hits))
                    self.queue.put(("progress", int((i+1)/len(profiles)*100)))
                self.queue.put(("done", "FOUND" if self.all_hits_data else "SAFE"))
            except Exception as e:
                self.queue.put(("msg", f"异常中断: {str(e)}"))
                self.queue.put(("done", "ERR"))

        threading.Thread(target=task, daemon=True).start()

    def generate_html_file(self, target_path):
        html_content = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>浏览器痕迹分析报告</title>
        <style>
            body {{ font-family: "Segoe UI", Arial, sans-serif; margin: 0; padding: 25px; background-color: #f5f7fa; }}
            .container {{ max-width: 1500px; margin: auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.06); }}
            h1 {{ color: #2c3e50; text-align: center; border-bottom: 2px solid #1890ff; padding-bottom: 15px; margin-top:0; font-size: 24px; }}
            .summary {{ font-size: 14px; color: #555; margin-bottom: 20px; display: flex; justify-content: space-between; background: #e6f7ff; padding: 12px 20px; border-radius: 4px; border-left: 4px solid #1890ff; }}
            .highlight {{ color: #ff4d4f; font-weight: bold; font-size: 16px; }}
            table {{ width: 100%; border-collapse: collapse; table-layout: fixed; box-shadow: 0 1px 3px rgba(0,0,0,0.02); }}
            th:nth-child(1), td:nth-child(1) {{ width: 10%; text-align: center; }}
            th:nth-child(2), td:nth-child(2) {{ width: 12%; text-align: center; }}
            th:nth-child(3), td:nth-child(3) {{ width: 10%; text-align: center; }}
            th:nth-child(4), td:nth-child(4) {{ width: 13%; text-align: center; }}
            th:nth-child(5), td:nth-child(5) {{ width: 55%; }}
            th, td {{ padding: 0 12px; height: 38px; line-height: 38px; border-bottom: 1px solid #f0f0f0; font-size: 13px; }}
            th {{ background-color: #1890ff; color: white; font-weight: 600; }}
            tr:hover {{ background-color: #fafafa; }}
            .url-cell {{ white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
            a {{ color: #1890ff; text-decoration: none; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
            a:hover {{ color: #40a9ff; text-decoration: underline; }}
        </style></head><body><div class="container">
            <h1>🔍 浏览器痕迹分析报告</h1>
            <div class="summary">
                <span>生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
                <span>共计发现留痕记录：<span class="highlight">{len(self.all_hits_data)}</span> 条</span>
            </div>
            <table><tr><th>浏览器</th><th>配置分身</th><th>记录类型</th><th>审计分类</th><th>详细地址</th></tr>"""
        
        for h in self.all_hits_data:
            html_content += f"<tr><td>{h[0]}</td><td>{h[1]}</td><td>{h[2]}</td><td><strong>{h[3]}</strong></td><td class='url-cell'><a href='{h[4]}' target='_blank' title='{h[4]}'>{h[4]}</a></td></tr>"
        html_content += "</table></div></body></html>"
        
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(html_content)

    def open_current_html(self):
        if os.path.exists(HTML_REPORT_PATH):
            clean_path = HTML_REPORT_PATH.replace('\\', '/')
            webbrowser.open(f"file:///{clean_path}")

    def _process_queue(self):
        try:
            processed_count = 0
            while processed_count < 100:
                try:
                    msg, val = self.queue.get_nowait()
                except queue.Empty:
                    break
                
                processed_count += 1
                if msg == "progress": self.pbar["value"] = val
                elif msg == "msg": self.status_lbl.config(text=val)
                elif msg == "data":
                    for h in val:
                        if h not in self.all_hits_data: self.all_hits_data.append(h)
                elif msg == "done":
                    self.btn_run.config(state="normal")
                    if val == "FOUND" or len(self.all_hits_data) > 0:
                        self.status_lbl.config(text="检测完成！已在临时目录生成无痕报告。")
                        self.btn_export.config(state="normal")
                        self.generate_html_file(HTML_REPORT_PATH)
                        clean_path = HTML_REPORT_PATH.replace('\\', '/')
                        webbrowser.open(f"file:///{clean_path}")
                    else:
                        self.status_lbl.config(text="扫描完成：系统处于纯净合规状态。")
                        messagebox.showinfo("检测结果", "未检测到任何相关的交互历史。")
        finally: 
            self.after(100, self._process_queue)

    def on_exit(self):
        ResourceManager.cleanup()
        self.destroy()

if __name__ == "__main__":
    app = App()
    app.mainloop()