
local table_concat = table.concat


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
local function parse_credential_line(line)
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
        print(line)
    --     local username, method, salt, cipher = parse_credential_line(line)

    --     if username then
    --         _M.credentials[username] = {
    --             method= method,
    --             salt= salt,
    --             cipher= cipher
    --         }
    --     end
    end

    file:close()

    return true
end

function _M.challenge(self, realm)
    ngx.header.www_authenticate = table_concat {
        "Basic realm=\"", realm, "\""}

    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

function _M.auth(self, realm)
    realm = realm or _M.default_realm

    local header = ngx.var.http_authorization
    if not header then
        return self:challenge(realm)
    end

    print(header)

    ngx.exit(ngx.OK)
end

function _M.new()
    return setmetatable({}, {__index= _M})
end


return _M
