@echo off
rem SPDX-License-Identifier: MIT
rem
rem Run or resume a kalkan audit unattended with the engine of the Claude Code plugin, from
rem PowerShell or cmd on Windows (docs/PLUGIN.md, "Unattended runs").
rem
rem Usage: kalkan-unattended.cmd TARGET [--profile fast or standard or deep] [options]
rem        kalkan-unattended.cmd devam [RUN_ID] [options]
rem        kalkan-unattended.cmd devam --run RUN_ID [options]
rem
rem The script runs venv\Scripts\kalkan.exe unattended in the plugin data folder with all its
rem arguments (--run included) and passes the exit code through. Every round names its run,
rem so one terminal per audit can run at the same time. devam without a run ID resumes the
rem newest run (runs\LATEST). It finds the plugin data folder like the sh
rem script kalkan-unattended next to it: the parent of its own folder when that folder holds
rem venv, else the variable CLAUDE_PLUGIN_DATA. kalkan-setup copies both scripts to the bin
rem folder of the plugin data folder, a path that stays the same after a plugin update.
rem cmd.exe interprets some characters in an argument without double quotes (ampersand, pipe,
rem angle brackets, caret, percent sign). Quote a target path with such a character, or use the
rem sh script in Git Bash.

setlocal
for %%I in ("%~dp0..") do set "KALKAN_DATA=%%~fI"
if exist "%KALKAN_DATA%\venv\" goto engine
if not defined CLAUDE_PLUGIN_DATA goto nodata
for %%I in ("%CLAUDE_PLUGIN_DATA%") do set "KALKAN_DATA=%%~fI"

:engine
set "KALKAN_ENGINE=%KALKAN_DATA%\venv\Scripts\kalkan.exe"
if not exist "%KALKAN_ENGINE%" goto noengine
"%KALKAN_ENGINE%" unattended %*
exit /b %ERRORLEVEL%

:nodata
>&2 echo kalkan-unattended: error: cannot find the kalkan plugin data folder. Type /kalkan unattended in Claude Code once: it installs the engine and this command, and prints the command to start.
exit /b 1

:noengine
>&2 echo kalkan-unattended: error: the kalkan engine is missing in %KALKAN_DATA%\venv. Type /kalkan unattended in Claude Code once: it installs the engine. Then start this command again.
exit /b 1
