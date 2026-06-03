import os
import time
import json
import re
import shutil
import sqlite3
import threading
import queue
import urllib.request
from datetime import datetime, timedelta
from urllib.parse import urlparse
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# =================================================
# 核心配置：路径与常量
# =================================================
CHINA_CONF = "accelerated-domains.china.conf"
CUSTOM_FILE = "custom-domains.conf"
TEMP_DIR = os.path.join(os.environ["TEMP"], "audit_pro_cache") # 使用系统临时目录更安全

# =================================================
# 1. 资源管理器：生命周期与运行环境监测
# =================================================
class ResourceManager:
    @staticmethod
    def initialize():
        """环境初始化与旧缓存冲洗"""
        if os.path.exists(TEMP_DIR):
            try: shutil.rmtree(TEMP_DIR)
            except: pass
        os.makedirs(TEMP_DIR, exist_ok=True)

        # 1. 下载/更新Github加速列表 (7天更新一次)
        url = "https://raw.githubusercontent.com/o484257-oss/dnsmasq-china-list/refs/heads/master/accelerated-domains.china.conf"
        if not os.path.exists(CHINA_CONF) or \
           (datetime.now() - datetime.fromtimestamp(os.path.getmtime(CHINA_CONF)) > timedelta(days=7)):
            try:
                with urllib.request.urlopen(url, timeout=10) as r:
                    with open(CHINA_CONF, 'wb') as f: f.write(r.read())
            except: pass

        # 2. 初始化自定义规则库
        if not os.path.exists(CUSTOM_FILE):
            with open(CUSTOM_FILE, "w", encoding="utf-8") as f:
                f.write("# 自定义审计规则库\n# 格式：域名=分类名称\n\n")
                f.write("heygen.com=AI视频(HeyGen)\ndreamina.capcut.com=AI绘画(剪映)\n")
                f.write("hailuoai.video=AI视频(海螺)\ndeepseek.com=DeepSeek\n")

    @staticmethod
    def cleanup():
        """物理粉碎临时文件"""
        if os.path.exists(TEMP_DIR):
            for _ in range(3): # 尝试多次防止文件占用
                try: 
                    shutil.rmtree(TEMP_DIR)
                    break
                except: time.sleep(0.5)

    @staticmethod
    def is_browser_running():
        """检测常见浏览器是否在运行"""
        browsers = ["chrome.exe", "msedge.exe", "brave.exe", "firefox.exe", "360se.exe", "360chrome.exe"]
        try:
            tasks = os.popen('tasklist').read().lower()
            return [b for b in browsers if b in tasks]
        except: return []

    @staticmethod
    def load_all_rules(use_china, use_custom):
        rules = {}
        if use_china and os.path.exists(CHINA_CONF):
            p = re.compile(r"server=/([^/]+)/")
            with open(CHINA_CONF, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    m = p.search(line)
                    if m: rules[m.group(1).lower()] = "国内加速域名"
        
        if use_custom and os.path.exists(CUSTOM_FILE):
            with open(CUSTOM_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        parts = line.split("=", 1)
                        rules[parts[0].strip().lower()] = parts[1].strip()
        return rules

# =================================================
# 2. 扫描内核：穿透历史、书签、下载
# =================================================
class ScannerCore:
    @staticmethod
    def get_profiles():
        profiles = []
        local = os.getenv('LOCALAPPDATA', '')
        appdata = os.getenv('APPDATA', '')
        
        # Chromium 系 (Chrome, Edge, Brave等)
        c_browsers = {
            "Chrome": r"Google\Chrome\User Data",
            "Edge": r"Microsoft\Edge\User Data",
            "Brave": r"BraveSoftware\Brave-Browser\User Data"
        }
        for name, sub in c_browsers.items():
            base = os.path.join(local, sub)
            if not os.path.exists(base): continue
            # 遍历分身 (Default, Profile 1, etc.)
            for item in os.listdir(base):
                p = os.path.join(base, item)
                if os.path.exists(os.path.join(p, "History")):
                    profiles.append({"b": name, "p": item, "path": p, "type": "C"})

        # Firefox
        ff_base = os.path.join(appdata, r"Mozilla\Firefox\Profiles")
        if os.path.exists(ff_base):
            for item in os.listdir(ff_base):
                p = os.path.join(ff_base, item)
                if os.path.exists(os.path.join(p, "places.sqlite")):
                    profiles.append({"b": "Firefox", "p": item, "path": p, "type": "F"})
        return profiles

    @staticmethod
    def scan(profile, rule_dict):
        hits = []
        targets = list(rule_dict.keys())

        # --- A. 数据库维度 (历史记录 & 下载列表) ---
        db_files = ["History"] if profile["type"] == "C" else ["places.sqlite"]
        for db_name in db_files:
            db_path = os.path.join(profile["path"], db_name)
            if not os.path.exists(db_path): continue
            
            tmp_db = os.path.join(TEMP_DIR, f"sc_{int(time.time()*1000)}.db")
            try:
                shutil.copy2(db_path, tmp_db)
                conn = sqlite3.connect(f"file:{tmp_db}?mode=ro", uri=True)
                cursor = conn.cursor()

                # 历史记录
                sql_hist = "SELECT url FROM urls" if profile["type"] == "C" else "SELECT url FROM moz_places"
                cursor.execute(sql_hist)
                for (url,) in cursor.fetchall():
                    ScannerCore._match(url, "历史记录", profile, rule_dict, targets, hits)

                # 下载记录 (Chromium专用逻辑)
                if profile["type"] == "C":
                    try:
                        cursor.execute("SELECT target_path, tab_url FROM downloads")
                        for path, url in cursor.fetchall():
                            ScannerCore._match(url or path, "下载文件", profile, rule_dict, targets, hits)
                    except: pass
                
                conn.close()
            except: pass
            finally: 
                if os.path.exists(tmp_db): os.remove(tmp_db)

        # --- B. JSON/结构化维度 (书签) ---
        if profile["type"] == "C":
            bk_path = os.path.join(profile["path"], "Bookmarks")
            if os.path.exists(bk_path):
                try:
                    with open(bk_path, 'r', encoding='utf-8', errors='ignore') as f:
                        data = json.load(f)
                        def walk(node):
                            if "url" in node:
                                ScannerCore._match(node["url"], "浏览器书签", profile, rule_dict, targets, hits)
                            if "children" in node:
                                for child in node["children"]: walk(child)
                        for key in ["bookmark_bar", "other", "synced"]:
                            if key in data["roots"]: walk(data["roots"][key])
                except: pass
        
        return list(set(hits)) # 物理去重

    @staticmethod
    def _match(url, info_type, profile, rule_dict, targets, hits):
        if not url or not url.startswith('http'): return
        try:
            domain = urlparse(url).netloc.lower()
            for t in targets:
                if domain == t or domain.endswith('.' + t):
                    hits.append((profile["b"], profile["p"], info_type, rule_dict[t], url))
                    break
        except: pass

# =================================================
# 3. GUI 界面：逻辑驱动与报告导出
# =================================================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("安全审计工具 Pro - 旗舰全能版")
        self.geometry("1200x800")
        self.configure(bg="#ffffff")
        
        ResourceManager.initialize()
        self.protocol("WM_DELETE_WINDOW", self.on_exit)
        
        self.queue = queue.Queue()
        self.vars = {}
        self._build_ui()
        self.after(100, self._process_queue)

    def _build_ui(self):
        # 头部导航
        header = tk.Frame(self, bg="#ffffff", pady=25); header.pack(fill=tk.X, padx=30)
        
        title_box = tk.Frame(header, bg="#ffffff"); title_box.pack(side=tk.LEFT)
        tk.Label(title_box, text="FULL SCOPE AUDIT", font=("Arial", 9, "bold"), fg="#ff4d4f", bg="white").pack(anchor="w")
        tk.Label(title_box, text="全维度审计方案", font=("微软雅黑", 16, "bold"), bg="white").pack(anchor="w")

        btn_box = tk.Frame(header, bg="#ffffff"); btn_box.pack(side=tk.RIGHT)
        self.btn_run = tk.Button(btn_box, text="🚀 开始精准检测", command=self.pre_run_check, bg="#1890ff", fg="white", 
                                font=("微软雅黑", 10, "bold"), relief=tk.FLAT, padx=25, pady=8, cursor="hand2")
        self.btn_run.pack(side=tk.RIGHT, padx=5)
        
        self.btn_export = tk.Button(btn_box, text="导出报告", command=self.export_report, bg="#52c41a", fg="white", 
                                   font=("微软雅黑", 10), relief=tk.FLAT, padx=20, pady=8, cursor="hand2", state="disabled")
        self.btn_export.pack(side=tk.RIGHT, padx=5)

        # 选项栏
        opt_frame = tk.Frame(self, bg="#f9f9f9", padx=20, pady=12); opt_frame.pack(fill=tk.X, padx=30, pady=5)
        tk.Label(opt_frame, text="监测范围：历史记录 + 浏览器书签 + 下载记录", font=("微软雅黑", 9), bg="#f9f9f9", fg="#888").pack(side=tk.LEFT)
        
        for k, t in [("china", "Github下载列表"), ("custom", "手动新增专项规则")]:
            var = tk.BooleanVar(value=True); self.vars[k] = var
            tk.Checkbutton(opt_frame, text=t, variable=var, bg="#f9f9f9", font=("微软雅黑", 9)).pack(side=tk.RIGHT, padx=15)

        # 进度与状态
        self.pbar = ttk.Progressbar(self, mode='determinate'); self.pbar.pack(fill=tk.X, padx=30, pady=(10, 0))
        self.status_lbl = tk.Label(self, text="系统就绪，等待指令...", bg="white", fg="#999", font=("微软雅黑", 9))
        self.status_lbl.pack(padx=30, anchor="w", pady=5)

        # 数据表
        frame = tk.Frame(self, bg="white"); frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=10)
        cols = ("B", "P", "T", "C", "U")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings")
        self.tree.heading("B", text="浏览器"); self.tree.heading("P", text="配置分身")
        self.tree.heading("T", text="记录类型"); self.tree.heading("C", text="审计分类"); self.tree.heading("U", text="详细地址")
        
        self.tree.column("B", width=100, anchor="center")
        self.tree.column("P", width=100, anchor="center")
        self.tree.column("T", width=100, anchor="center")
        self.tree.column("C", width=130, anchor="center")
        self.tree.column("U", width=700, anchor="w")
        
        scroll = ttk.Scrollbar(frame, command=self.tree.yview); self.tree.configure(yscroll=scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def pre_run_check(self):
        """运行前环境检查"""
        running = ResourceManager.is_browser_running()
        if running:
            msg = f"检测到浏览器正在运行：\n{', '.join(running)}\n\n关闭浏览器可以确保【书签】和【最新历史】100%被捕获。是否强制开始扫描？"
            if not messagebox.askokcancel("精准审计提示", msg):
                return
        self.run()

    def run(self):
        rules = ResourceManager.load_all_rules(self.vars["china"].get(), self.vars["custom"].get())
        if not rules:
            messagebox.showerror("错误", "未加载到任何规则库，扫描取消。")
            return
        
        self.btn_run.config(state="disabled", bg="#d9d9d9")
        self.btn_export.config(state="disabled")
        self.tree.delete(*self.tree.get_children())
        
        def task():
            try:
                profiles = ScannerCore.get_profiles()
                if not profiles:
                    self.queue.put(("msg", "未在系统中发现支持的浏览器配置文件"))
                    self.queue.put(("done", None))
                    return

                for i, p in enumerate(profiles):
                    self.queue.put(("msg", f"正在穿透扫描: {p['b']} ({p['p']})"))
                    hits = ScannerCore.scan(p, rules)
                    if hits: self.queue.put(("data", hits))
                    self.queue.put(("progress", int((i+1)/len(profiles)*100)))
                
                self.queue.put(("done", "OK"))
            except Exception as e:
                self.queue.put(("msg", f"扫描异常结束: {str(e)}"))
                self.queue.put(("done", "ERR"))

        threading.Thread(target=task, daemon=True).start()

    def export_report(self):
        """导出精美 TXT 报告"""
        items = self.tree.get_children()
        if not items: return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            initialfile=f"全维度审计报告_{datetime.now().strftime('%Y%m%d')}.txt"
        )
        
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(f"=== 安全审计报告 ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ===\n")
                    f.write("-" * 120 + "\n")
                    f.write(f"{'浏览器':<10} | {'分身':<10} | {'记录类型':<10} | {'审计分类':<15} | {'URL地址'}\n")
                    f.write("-" * 120 + "\n")
                    for it in items:
                        v = self.tree.item(it)["values"]
                        f.write(f"{str(v[0]):<10} | {str(v[1]):<10} | {str(v[2]):<10} | {str(v[3]):<15} | {v[4]}\n")
                messagebox.showinfo("成功", "审计报告已生成。")
            except Exception as e:
                messagebox.showerror("导出失败", str(e))

    def _process_queue(self):
        try:
            while True:
                msg, val = self.queue.get_nowait()
                if msg == "progress": self.pbar["value"] = val
                elif msg == "msg": self.status_lbl.config(text=val)
                elif msg == "data":
                    for h in val: self.tree.insert("", tk.END, values=h)
                elif msg == "done":
                    self.btn_run.config(state="normal", bg="#1890ff")
                    self.btn_export.config(state="normal")
                    self.status_lbl.config(text="扫描完成！" if val == "OK" else "扫描受阻退出")
                    ResourceManager.cleanup()
        except: pass
        finally: self.after(100, self._process_queue)

    def on_exit(self):
        ResourceManager.cleanup()
        self.destroy()

if __name__ == "__main__":
    app = App()
    app.mainloop()