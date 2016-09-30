
local tab_concat = table.concat
local str_find = string.find
local str_sub = string.sub
local str_gsub = string.gsub


local _M = {
    credentials= {},
    default_realm= "Default Realm",
}


--
-- See http://nginx.org/en/docs/http/ngx_http_auth_basic_module.html#auth_basic_user_file
-- for more information
local function parse_line(line)
    local states = {
        sw_start= 0,
        sw_user= 1,
        sw_before_method= 2,
        sw_method= 3,
        sw_salt= 4,
        sw_cipher= 5,
        sw_done= 6,
    }

    local user_start, user_end, method_start, method_end
    local salt_start, salt_end, cipher_start, cipher_end
    local user, method, salt, cipher

    local state, sep = states.sw_start, ""

    for i = 1, #line, 1 do
        local c = line:sub(i, i)

        if state == states.sw_start then
            if c == "#" then  -- skip comment
                return nil, "a comment line"
            elseif c == ":" then -- empty user
                return nil, "empty user"
            elseif c ~= " " and c ~= "\t" then
                state, user_start = states.sw_user, i
            end

        elseif state == states.sw_user then
            if c == ":" then
                state, user_end = states.sw_before_method, i-1
            end

        elseif state == states.sw_before_method then
            if c == "$" or c == "{" then
                state, method_start, sep = states.sw_method, i+1, c
            else
                state, method, cipher_start = states.sw_cipher, "crypt", i
            end

        elseif state == states.sw_method then
            if c == "$" and sep == "$" then
                state, method_end, salt_start = states.sw_salt, i-1, i+1
            elseif c == "}" and sep == "{" then
                state, method_end, cipher_start = states.sw_cipher, i-1, i+1
            end

        elseif state == states.sw_salt then
            if c == "$" then
                state, salt_end, cipher_start = states.sw_cipher, i-1, i+1
            end

        elseif state == states.sw_cipher then
            if c == ":" then
                state, cipher_end = states.sw_done, i-1
            elseif i == #line then
                state, cipher_end = states.sw_done, i
            end

        elseif state == states.sw_done then
            break
        end
    end

    if state ~= states.sw_done then
        return nil, "invalid format"
    end

    -- user
    user = line:sub(user_start, user_end)

    -- method
    if method_start then
        method = line:sub(method_start, method_end)
    end
    method = method:lower()
    
    -- cipher
    cipher = line:sub(cipher_start, cipher_end)

    -- salt and final cipher
    if method == "apr1" then 
        if not salt_start then
            return nil, "\"apr1\" should carry plain salt"
        end
        salt = line:sub(salt_start, salt_end)

        return user, method, salt, cipher

    elseif method == "plain" then         
        return user, method, "", cipher

    elseif method == "sha" then
        -- the {SHA} method shouldn't be used for security reasons as it's
        -- vulnerable to attackes using rainbow tables. Use either {SSHA} or
        -- {MD5} instead if you care about compatibility with other platforms,
        -- or `crypt()` schemes provided by your OS if you aren't
        cipher = ngx.decode_base64(cipher)
        if not cipher then
            return nil, "sha cipher invalid"
        end
        return user, method, "", cipher

    elseif method == "crypt" then
        if #cipher ~= 13 then
            return nil, "crypt cipher invalid"
        end
        return user, method, cipher:sub(1, 2), cipher:sub(3)

    elseif method == "ssha" then
        -- a {SSH} password is just a {SSHA} one with empty salt
        local bin = ngx.decode_base64(cipher)
        if not bin or #bin < 20 then
            return nil, "{SSHA} cipher invalid"
        end

        return user, method, bin:sub(21), bin:sub(1, 20)

    else
        return nil, "encrpytion method not support"
    end
end


local function validate_plain(passwd, salt, cipher)
    return (passwd == cipher)
end


local function validate_sha(passwd, salt, cipher)
    return (ngx.sha1_bin(passwd) == cipher)
end


local function validate_ssha(passwd, salt, cipher)
    return (ngx.sha1_bin(passwd .. salt) == cipher)
end


local function validate_apr1(passwd, salt, cipher)
    -- Apache's apr1 crypt is Poul-Henning Kamp's MD5 crypt
    -- algorithm with $apr1$ magic.
    return false
end


local function validate_crypt(passwd, salt, cipher)
    --
    return false
end


local validators = {
    plain= validate_plain,
    sha=validate_sha,
    ssha= validate_ssha,
    apr1= validate_apr1,
    crypt= validate_crypt,
}

local function validate(credentials, user, passwd)
    if not credentials[user] then
        return false
    end

    local cred = credentials[user]
    return validators[cred.method](passwd, cred.salt, cred.cipher)
end


local function challenge(realm)
    ngx.header.www_authenticate = tab_concat {
        "Basic realm=\"", realm, "\""}

    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end


function _M.setup(args)
    if not args.user_file then
        return nil, "\"user_file\" needed"
    end

    local user, method, salt, cipher

    local file, err = io.open(args.user_file, "r")
    if not file then
        return nil, err
    end

    local users = 0
    for line in file:lines() do
        user, method, salt, cipher = parse_line(line)

        if user then
            _M.credentials[user] = {method= method, salt= salt, cipher= cipher}
            users = users + 1
        else
            print("[" .. line .. "] error: " .. method)
        end
    end

    file:close()

    if users == 0 then
        return false, "\"user_file\" no valid lines"
    end

    return true
end


function _M.auth(self, realm)
    realm = realm or _M.default_realm

    -- credentials
    local header = ngx.var.http_authorization
    if not header then
        return challenge(realm)
    end

    local prefix = "Basic "
    if str_sub(header, 1, #prefix) ~= prefix then
        return challenge(realm)
    end

    -- base64-user-pass
    local b64_userpass = str_gsub(str_sub(header, #prefix+1), " ", "")

    -- user-pass
    local userpass = ngx.decode_base64(b64_userpass)
    if not userpass then
        return challenge(realm)
    end

    local colon = str_find(userpass, ":")
    if not colon then
        return challenge(realm)
    end

    local user = str_sub(userpass, 1, colon - 1)
    local passwd = str_sub(userpass, colon + 1)

    if not validate(self.credentials, user, passwd) then
        return challenge(realm)
    end

    return ngx.exit(ngx.OK)
end


function _M.new()
    return setmetatable({}, {__index= _M})
end


return _M
