@echo off
rem SPDX-License-Identifier: MIT
rem
rem Audit a folder or a git URL with one command, with the engine of the Claude Code plugin,
rem from PowerShell or cmd on Windows (docs/PLUGIN.md, "One-command audit").
rem
rem Usage: kalkan-audit.cmd TARGET [--profile fast or standard or deep] [--tools-only]
rem                       [--open] [--yes] [--no-latest] [--max-hours N] [--json]
rem        kalkan-audit.cmd devam [RUN_ID]
rem
rem The script runs venv\Scripts\kalkan.exe audit in the plugin data folder with all its
rem arguments and passes the exit code through. kalkan audit checks the setup, creates the
rem run, runs the scanners and SCA, then starts Claude Code rounds that are bound to the run
rem and wait through usage-limit resets. At the end it prints the deliverables and a short
rem summary. The option --tools-only needs no Claude Code. Exit codes: 0 done, 1 incomplete,
rem stopped or failed, 2 usage, 5 setup needed. It finds the plugin data folder like the sh
rem script kalkan-audit next to it: the parent of its own folder when that folder holds venv,
rem else the variable CLAUDE_PLUGIN_DATA. kalkan-setup copies both scripts to the bin folder of
rem the plugin data folder, a path that stays the same after a plugin update.
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
"%KALKAN_ENGINE%" audit %*
exit /b %ERRORLEVEL%

:nodata
>&2 echo kalkan-audit: error: cannot find the kalkan plugin data folder. Install kalkan first: run scripts\install.ps1, or type /kalkan unattended in Claude Code once. Both install the engine and this command.
exit /b 1

:noengine
>&2 echo kalkan-audit: error: the kalkan engine is missing in %KALKAN_DATA%\venv. Install kalkan first: run scripts\install.ps1, or type /kalkan unattended in Claude Code once. Then start this command again.
exit /b 1
