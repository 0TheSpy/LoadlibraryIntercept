# LoadlibraryIntercept
Pause process when target module is loaded

![Screenshot](https://i.imgur.com/yIWyMMm.png)

Arguments:

-t "F:/Counter-Strike Source 4044/hl2.exe -game cstrike -insecure"

-m "steam_api.dll" (optional) - module to breakpoint
OR
-m "everymodule" (optional) - breakpoint on each LdrLoadDLL and LdrUnloadDll

-e (optional) - inject into existing process

-hwid (optional) - hook NtDeviceIoControlFile and spoof SerialNumber

-regmon (optional) - hook NtQueryObject

![Screenshot](https://i.imgur.com/9HtcwNB.png)
