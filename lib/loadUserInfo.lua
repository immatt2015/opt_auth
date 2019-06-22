local json = require "cjson"

local exports = {
    version = "1.0.0" -- 让 opm 自动识别入口文件和版本号
}

local function file_load(filename)
    local file
    if filename == nil then
        file = io.stdin
    else
        local err
        file, err = io.open(filename, "rb")
        if file == nil then
            error(("Unable to read '%s': %s"):format(filename, err))
        end
    end
    local data = file:read("*a")

    if filename ~= nil then
        file:close()
    end

    if data == nil then
        error("Failed to read " .. filename)
    end

    return data
end

local function reloadUidInfo()
    local jwtCache = ngx.shared.jwt
    if jwtCache == nil then
        return
    end

    if ngx.var.user_info_path == nil then
        return
    end
    local json_text = file_load(ngx.var.user_info_path)
    if json_text == nil then
        return
    end
    local t = json.decode(json_text)

    jwtCache:flush_all()

    for uid, content in pairs(t) do
        jwtCache:set(uid, json.encode(content))
    end
end

function exports.reload()
    reloadUidInfo()
    ngx.timer.every(10, reloadUidInfo)
end

return exports
