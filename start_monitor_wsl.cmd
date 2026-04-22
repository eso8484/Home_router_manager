@echo off
setlocal

wsl.exe -d Ubuntu-24.04 -u eso -- bash -lc "cd /mnt/c/Users/enejo/Downloads/monitors_network && chmod +x run_monitor.sh && ./run_monitor.sh"

endlocal
