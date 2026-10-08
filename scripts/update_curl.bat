@echo off
rem Runs scripts\update_curl.sh with Git Bash so it can be started from cmd.exe.
rem Usage:
rem   scripts\update_curl.bat ^<next_version^> [current_version]
rem   scripts\update_curl.bat --continue
setlocal

rem Prefer the bash.exe shipped with Git for Windows; System32\bash.exe is WSL.
set "BASH_EXE="
for /f "delims=" %%G in ('where git 2^>nul') do (
  if not defined BASH_EXE if exist "%%~dpG..\bin\bash.exe" set "BASH_EXE=%%~dpG..\bin\bash.exe"
)
if not defined BASH_EXE if exist "%ProgramFiles%\Git\bin\bash.exe" set "BASH_EXE=%ProgramFiles%\Git\bin\bash.exe"
if not defined BASH_EXE (
  echo ERROR: Git Bash not found. Install Git for Windows.
  exit /b 1
)

"%BASH_EXE%" "%~dp0update_curl.sh" %*
exit /b %ERRORLEVEL%
