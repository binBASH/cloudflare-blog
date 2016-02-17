-- Advanced packet processing script
io.write("Loaded LUA Advanced Packet Processing\n");

local apkt = {}

function apkt.hex_dump(str)
    local len = string.len(str)
    local dump = ""
    local hex = ""
    local asc = ""

    for i = 1, len do
        if 1 == i % 16 then
            dump = dump .. hex .. asc .. "\n"
            hex = string.format("%04X   ", i - 1)
            asc = ""
        end
        
        local ord = string.byte(str, i)
        hex = hex .. string.format("%02X ", ord)
        if ord >= 32 and ord <= 126 then
            asc = asc .. string.char(ord)
        else
            asc = asc .. "."
        end
        if 1 == i % 16 then
            asc = "  " .. asc
        end
    end

    
    return dump .. hex
            .. string.rep("   ", 16 - len % 16) .. asc
end

return apkt
