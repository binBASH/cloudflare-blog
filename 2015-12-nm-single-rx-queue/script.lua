-- LUA base loading script 
m = require "apkt"

io.write("LUA scripts loaded succesfully\n");

function callback(buf, len)
    local ret
    print(m.hex_dump(buf))
    ret = m.filter(buf)
    print("Pkt len: " .. len)
    return ret
end

function reload_all()
    print "Reloading LUA packages"
    package.loaded.app = nil
    m = require "apkt"
    return 0
end
