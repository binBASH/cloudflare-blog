-- LUA base loading script 
m = require "apkt"

io.write("LUA scripts loaded succesfully\n");

function callback(buf, len)
    print(m.hex_dump(buf))
    print("Pkt len: " .. len)
    return 0
end

function reload_all()
    print "Reloading LUA packages"
    package.loaded.app = nil
    m = require "apkt"
    return 0
end
