@echo off
chcp 65001 >nul
title Office助手卸载程序

echo ========================================
echo           Office助手卸载程序
echo ========================================
echo.

echo [权限检查] 验证管理员权限...
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 需要管理员权限以卸载
    echo 请右键点击选择"以管理员身份运行"
    pause
    exit /b 1
)

echo [服务停止] 停止运行的服务...
taskkill /f /im OfficeHelper.exe >nul 2>&1
echo 等待进程完全退出...
timeout /t 3 /nobreak >nul

echo [启动项] 删除计划任务...
schtasks /delete /tn "OfficeHelper" /f >nul 2>&1
echo 删除注册表项...
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OfficeHelper" /f >nul 2>&1
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "OfficeHelper" /f >nul 2>&1

echo [文件清理] 删除程序文件...
if exist "%ProgramData%\Microsoft\OfficeHelper" (
    rmdir /s /q "%ProgramData%\Microsoft\OfficeHelper" >nul 2>&1
    echo 程序目录已删除
)

if exist "C:\Windows\Temp\office_helper.log" (
    del "C:\Windows\Temp\office_helper.log" >nul 2>&1
    echo 日志文件已删除
)

echo.
echo ========================================
echo          卸载完成！
echo ========================================
echo 所有相关文件和注册表项已清理
echo 按任意键退出...
pause >nul
exit