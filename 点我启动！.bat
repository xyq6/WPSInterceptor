@echo off
chcp 65001 >nul
title Office助手安装程序

echo ========================================
echo           Office助手安装程序
echo       自动拦截WPS，保留希沃白板
echo ========================================
echo.

echo [权限检查] 验证管理员权限...
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 需要管理员权限以安装系统服务
    echo 请右键点击选择"以管理员身份运行"
    echo.
    pause
    exit /b 1
)

echo [文件检查] 检查程序文件...
if not exist "WPSInterceptor.exe" (
    echo [错误] 未找到主程序文件 WPSInterceptor.exe
    echo 请确保此批处理文件与主程序在同一目录
    pause
    exit /b 1
)

echo [进程检查] 终止可能冲突的进程...
taskkill /f /im "WPSInterceptor.exe" >nul 2>&1
taskkill /f /im "OfficeHelper.exe" >nul 2>&1
timeout /t 2 /nobreak >nul

echo [目录创建] 创建程序目录...
if not exist "%ProgramData%\Microsoft\OfficeHelper" (
    mkdir "%ProgramData%\Microsoft\OfficeHelper"
)

echo [文件复制] 安装程序文件...
copy "WPSInterceptor.exe" "%ProgramData%\Microsoft\OfficeHelper\OfficeHelper.exe" >nul
if %errorlevel% neq 0 (
    echo [错误] 复制文件失败，请检查权限
    echo 可能的原因：
    echo 1. 文件被其他程序占用
    echo 2. 杀毒软件拦截
    echo 3. 磁盘空间不足
    echo.
    echo 请关闭所有可能使用该文件的程序后重试
    pause
    exit /b 1
)

echo [启动项] 创建系统启动项...
schtasks /create /tn "OfficeHelper" /tr "\"%ProgramData%\Microsoft\OfficeHelper\OfficeHelper.exe\"" /sc onlogon /ru System /f >nul 2>&1
if %errorlevel% equ 0 (
    echo [成功] 计划任务创建完成
) else (
    echo [备用方案] 使用注册表启动项
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OfficeHelper" /t REG_SZ /d "\"%ProgramData%\Microsoft\OfficeHelper\OfficeHelper.exe\"" /f >nul 2>&1
)

echo [服务启动] 启动监控服务...
start /min "" "%ProgramData%\Microsoft\OfficeHelper\OfficeHelper.exe"

echo.
echo ========================================
echo          安装完成！
echo ========================================
echo.
echo 功能说明：
echo • 自动拦截WPS并显示验证提示
echo • 完全保留希沃白板功能  
echo • 后台静默运行
echo • 开机自动启动
echo.
echo 验证方法：
echo 1. 重启电脑
echo 2. 尝试打开WPS软件测试
echo 3. 检查任务管理器中的OfficeHelper进程
echo.
echo 卸载方法：
echo 运行 Uninstall_OfficeHelper.bat
echo.
echo 按任意键退出...
pause >nul
exit