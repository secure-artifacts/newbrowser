@echo off
chcp 65001 >nul
title 一键打包工具（稳定版-无图标）

echo =====================================
echo      一键打包工具（稳定版）
echo =====================================

:: ===== 0. 检测 Python =====
echo.
echo 检测 Python 环境...

set PYTHON_CMD=

python --version >nul 2>&1
if %ERRORLEVEL%==0 set PYTHON_CMD=python

if not defined PYTHON_CMD (
    if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" set PYTHON_CMD="%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" set PYTHON_CMD="%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
    if exist "C:\Python311\python.exe" set PYTHON_CMD="C:\Python311\python.exe"
    if exist "C:\Python310\python.exe" set PYTHON_CMD="C:\Python310\python.exe"
)

if not defined PYTHON_CMD (
    py --version >nul 2>&1
    if %ERRORLEVEL%==0 set PYTHON_CMD=py
)

if not defined PYTHON_CMD (
    echo.
    echo ❌ 未检测到 Python 环境
    echo.
    echo 👉 请安装 Python（3.10.11版本打包稳定）
    echo.
    echo 👉 安装时切记勾选 Add Python to PATH
    echo.
    echo 👉 安装完毕之后请重新运行此脚本。
    echo.
    echo ====== 输入Y可打开Python官网页面进行下载3.10.11  ======
    echo.
    choice /M "是否打开下载页面?"

    IF ERRORLEVEL 2 (
        pause
        exit
    )

    start https://www.python.org/downloads/release/python-31011/
    pause
    exit
)

echo ✅ 使用 Python: %PYTHON_CMD%

:: ===== 1. 虚拟环境 =====
echo.
if exist venv\Scripts\python.exe (
    echo ⚡ 使用已有虚拟环境
) else (
    echo 创建虚拟环境...
    %PYTHON_CMD% -m venv venv

    if not exist venv\Scripts\python.exe (
        echo ❌ 虚拟环境创建失败
        pause
        exit
    )
)

set PY=venv\Scripts\python.exe

:: ===== 2. pip 修复 =====
echo.
echo 修复 pip...
%PY% -m ensurepip >nul 2>&1
%PY% -m pip install --upgrade pip

:: ===== 3. 安装依赖 =====
echo.
echo 安装依赖...

if exist requirements.txt (
    %PY% -m pip install -r requirements.txt
    IF %ERRORLEVEL% NEQ 0 (
        echo ❌ 依赖安装失败
        pause
        exit
    )
) else (
    echo ⚠️ 未找到 requirements.txt，安装核心依赖
    %PY% -m pip install requests pyinstaller==6.6.0

    IF %ERRORLEVEL% NEQ 0 (
        echo ❌ 依赖安装失败
        pause
        exit
    )
)

:: ===== 4. 入口文件检测 =====
echo.
echo 检测入口文件...

set ENTRY=

if exist src\browser_Gui.py set ENTRY=src\browser_Gui.py
if exist browser_Gui.py set ENTRY=browser_Gui.py

if not defined ENTRY (
    echo ❌ 未找到 browser_Gui.py
    echo 👉 请确认文件在 src 或当前目录
    pause
    exit
)

echo 使用入口文件: %ENTRY%

:: ===== 5. 打包（无图标稳定版）=====
echo.
echo 开始打包...

%PY% -m PyInstaller ^
-F -w %ENTRY% ^
--name BrowserAnalyzer ^
--clean ^
--noconfirm

IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo ❌ 打包失败
    echo 👉 可能被杀毒软件拦截
    pause
    exit
)

:: ===== 6. 整理输出 =====
echo.
echo 整理输出...

set OUT=release

if exist %OUT% rmdir /s /q %OUT%
mkdir %OUT%

move /Y dist\BrowserAnalyzer.exe %OUT%\ >nul


:: 使用说明
(
echo 安全审计工具 Pro 使用说明
echo.
echo 1. 双击 BrowserAnalyzer.exe 启动。
echo 2. 点击 "开始精准检测"，若提示浏览器运行中，建议关闭后重试。
echo 3. 扫描完成后，点击 "导出报告" 保存审计清单。
echo.
echo [监测维度]
echo 本工具覆盖：历史记录、浏览器书签、下载列表。
echo.
echo [自定义规则库]
echo 可使用记事本编辑 custom-domains.conf
echo 编辑格式：域名=分类
echo.
echo 示例：
echo openai.com=AI工具
echo github.com=代码仓库
echo google.com=搜索
echo youtube.com=视频
)> %OUT%\使用说明.txt
:: 规则文件
if exist custom_rules.conf copy /Y custom_rules.conf %OUT%\ >nul


:: ===== 7. 清理 =====
echo 清理缓存...

if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist BrowserAnalyzer.spec del /f /q BrowserAnalyzer.spec

:: ===== 8. 完成 =====
echo.
echo =====================================
echo ✅ 打包完成！
echo 👉 release 文件夹可直接使用
echo =====================================

start "" %OUT%

pause