local otp = require "otp"
local json = require "cjson"
local jwt = require "resty.jwt"

local exports = {}

function exports.req_auth(origin_uri, tip)
    if origin_uri == nil then
        origin_uri = "/"
    end
    if tip == nil then
        tip = ""
    end
    return {
        false,
        table.concat(
            {
                "<html>",
                '<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />',
                "<style>body{padding:2rem 1rem;background-color:black}.container{display:flex;justify-content:center;align-items:center}form{bottom:50%;max-width:30rem;padding:1.5rem 2rem;background-color:white;border-radius:8px;box-shadow:0 4px 20px rgba(0,0,0,0.15)}form h1{margin-bottom:1.5rem;padding-bottom:1rem;border-bottom:1px solid var(--gray-lighter);font-size:var(--font-size-3);text-align:center}input{background-repeat:no-repeat;background-position:right 1rem center;background-size:0.75rem;width:40em}input::-ms-input-placeholder{text-align:center}input::-webkit-input-placeholder{text-align:center}</style>",
                "<body>",
                '<div class="container">',
                '<form method="POST" enctype="application/x-www-form-urlencoded" action="' .. origin_uri .. '">',
                "<h1>鉴权</h1>",
                '<p><input type="text"id="required-input"name="user"required placeholder="用户名"></p>',
                '<p><input type="password"id="optional-input"name="passwd"required placeholder="密码"></p>',
                '<p><input type="text"id="disabled-input"name="code"placeholder="手机验证码"></p>',
                '<p><input type="submit"value="认证"id="submit"></p>',
                "<p><span style='color:#F00'>" .. tip .. "</span></p>",
                "</form>",
                "</div>",
                "</body></html>"
            }
        )
    }
end

function exports.remove_auth()
    ngx.header["Set-Cookie"] = "auth=;path=/"
end

function exports.do_auth(jwt_key)
    local auth = ngx.var.cookie_auth
    local jwtCache = ngx.shared.jwt

    if jwt_key == nil then
        ngx.exit(511)
    end

    local headers = ngx.req.get_headers()
    local ip = headers["X-REAL-IP"] or headers["X_FORWARDED_FOR"] or ngx.var.remote_addr
    local user_agent = headers["user-agent"]
    local origin_uri = ngx.var.request_uri
    if ip == nil then
        ngx.exit(505)
    end

    if auth ~= nil and auth ~= "" then
        local jwt_payload = jwt:verify(jwt_key, auth)
        if
            jwt_payload.verified == true and jwt_payload.payload.ip == ip or
                jwtCache:get(jwt_payload.payload.user) ~= nil
         then
            return {true}
        else
            remove_auth()

            return exports.req_auth(origin_uri, "登陆过期")
        end
    end

    ngx.req.read_body()
    local body_params = ngx.req.get_post_args()
    if body_params ~= nil then
        local userInfo
        if body_params["user"] ~= nil and jwtCache:get(body_params["user"]) ~= nil then
            userInfo = json.decode(jwtCache:get(body_params["user"]))
        end
        if
            body_params["user"] == nil or body_params["passwd"] == nil or body_params["code"] == nil or userInfo == nil or
                ngx.md5(body_params["passwd"]) ~= userInfo.passwd
         then
            local tip = ""
            if body_params["user"] ~= nil then
                tip = "鉴权失败!"
            end
            return exports.req_auth(origin_uri, tip)
        end

        local user = body_params["user"]

        local OTP = otp.totp_init(userInfo["totp_key"])

        -- local url = OTP:get_qr_url("OpenResty-TOTP", userInfo['totp_key'])

        if OTP:verify_token(body_params["code"]) == true then
            ngx.header["Set-Cookie"] =
                "auth=" ..
                jwt:sign(
                    jwt_key,
                    {
                        header = {typ = "JWT", alg = "HS256"},
                        payload = {
                            role = userInfo.role,
                            ip = ip,
                            user = body_params["user"],
                            sec = ngx.md5(table.concat({ip, "-", user_agent}))
                        }
                    }
                )
            return {true}
        end
    end
    return {false}
end

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

function exports.reload_user_info(premature, user_info_path)
    local jwtCache = ngx.shared.jwt
    if jwtCache == nil then
        return
    end

    if user_info_path == nil then
        return
    end
    local json_text = file_load(user_info_path)
    if json_text == nil then
        return
    end
    local t = json.decode(json_text)

    jwtCache:flush_all()

    for uid, content in pairs(t) do
        jwtCache:set(uid, json.encode(content))
    end
end

return exports
