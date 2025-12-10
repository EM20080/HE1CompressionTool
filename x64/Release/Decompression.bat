@echo off
setlocal enabledelayedexpansion

set "filelist="

for /f "delims=" %%f in ('dir /s /b *.ar *.arl *.dds *.hkx *.xml *.ar.?? 2^>nul') do (
    set "filelist=!filelist! "%%f""
)

HE1CompressionTool.exe -decompress !filelist!

pause
