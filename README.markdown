# lua-win32

```lua
local win32 = require("win32")
print(win32.get_current_process_id())
for process in win32.iter_process(0) do
print("name: "..process.szExeFile.."  id: "..tostring( process.th32ProcessID))
end

for module in win32.iter_module(0) do
print("name: "..module.szModule.."  path: "..module.szExePath)
end

for thread in win32.iter_thread(0) do
print("threadid: "..thread.th32ThreadID.."  pid: "..thread.th32OwnerProcessID)
end
win32.lock_workstation()
```