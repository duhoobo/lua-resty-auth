
local tab_concat = table.concat
local str_find = string.find
local str_sub = string.sub
local str_gsub = string.gsub


local _M = {
    credentials= {},
    default_realm= "Default Realm",
}


-- @return: username, method, salt, cipher
-- line formats: TODO
--      user:$apr1$salt$cipher
--      user:{PLAIN}cipher
--      user:{SSHA}base64(SHA1(key+salt)+salt)
--      user:{SHA}base64(SHA1(key))
local function parse_line(line)
    return "admin", "plain", "", "admin"
end


local function validate_plain(user, passwd, salt, cipher)
    print(user, passwd, salt, cipher)
    return passwd == cipher
end

local function validate_apr1(user, passwd, salt, cipher)
end

local function validate_sha(user, passwd, salt, chiper)
end

local function validate_ssha(user, passwd, salt, cipher)
end


local validators = {
    plain= validate_plain,
    apr1= validate_apr1,
    sha=validate_ssha,
    ssha= validate_ssha,
}

local function validate(credentials, user, passwd)
    if not credentials[user] then
        return false
    end

    local cred = credentials[user]
    return validators[cred.method](user, passwd, cred.salt, cred.cipher)
end


local function challenge(realm)
    ngx.header.www_authenticate = tab_concat {
        "Basic realm=\"", realm, "\""}

    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end


function _M.setup(args)
    if not args.user_file then
        return nil, "\'user_file\' needed"
    end

    local file, err = io.open(args.user_file, "r")
    if not file then
        return nil, err
    end

    for line in file:lines() do
        local user, method, salt, cipher = parse_line(line)

        if user then
            _M.credentials[user] = {
                method= method,
                salt= salt,
                cipher= cipher
            }
        end
    end

    file:close()

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
