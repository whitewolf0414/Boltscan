-- hello.lua — Minimal Bolt Scan example script (Lua)
--
-- Usage contract: Bolt Scan passes <target> and <port> as command-line
-- arguments. Print a single line to stdout as the script result.
--
-- Run manually: lua hello.lua 192.168.1.1 80

local target = arg[1]
local port   = arg[2]
print("Hello from Lua: " .. target .. ":" .. port)
