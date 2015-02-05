local math_seed = math.randomseed
local math_rand = math.random
local tab_concat = table.concat
local str_sub = string.sub
local str_find = string.find


local _M = {
    shm= nil
    expires= nil,
    replays= nil,
    timeout= nil,
    salt= nil,
    credentials= {},
    default_realm= "realm",
}


local function parse_line(line)
    local states = {
        sw_start= 0,
        sw_user= 1,
        sw_realm= 2,
        sw_cipher= 3,
        sw_done = 4,
    }

    local user_start, user_end, realm_start, realm_end
    local cipher_start, cipher_end
    local user, realm, cipher

    local state = states.sw_start

    for i = 1, #line, 1 do
        local c = line:sub(i, i)

        if state == states.sw_start then 
            if c == "#" then -- skip comment
                return nil, "a comment line"
            elseif c == ":" then
                return nil, "empty user"
            elseif c ~= " " and c ~= "\t" then
                state, user_start = states.sw_user, i
            end

        elseif state == states.sw_user then
            if c == ":" then
                state, user_end, realm_start = states.sw_realm, i-1, i+1
            end

        elseif state == states.sw_realm then
            if c == ":" then
                state, realm_end, cipher_start = states.sw_cipher, i-1, i+1
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

    user = line:sub(user_start, user_end)
    realm = line:sub(realm_start, realm_end)
    cipher = line:sub(cipher_start, cipher_end)

    return user, realm, cipher
end


local function next_nonce(shared_dict, salt, timeout)
    local ok, gc, err, now, forcible, nonce

    gc, err = shared_dict:incr("global_counter", 1)
    now = ngx.now()

    nonce = ngx.encode_base64(ngx.hmac_sha1(salt, now .. ":" .. gc))

    ok, err, forcible = shared_dict:set(nonce, 0, now + timeout)
    if not ok then
        return nil, err
    end

    return nonce
end


-- nonce stale or not
local function nonce_stale(shared_dict, nonce, timeout, replays, expires)
    local nc, err = shared_dict:incr(nonce, 1)
    if not nc or nc > replays then
        return true
    end

    local val, flags = shared_dict:get(nonce)
    if not val then  -- stale or not existent
        return true
    end

    if flags - timeout + expires <= ngx.now() then
        shared_dict:delete(key)
        return true
    end

    return false
end


-- shm, user_file, expires, replays, timeout
function _M.setup(args)
    if not args.shm then
        return nil, "\"shm\" needed"
    end

    if not ngx.shared[args.shm] then
        return nil, "shm \"" .. args.shm .. "\" not exists"
    end

    _M.shm = args.shm

    if not args.user_file then
        return nil, "\"user_file\" needed"
    end

    local user, realm, cipher

    local file, err = io.open(args.user_file, "r")
    if not file then
        return nil, err
    end

    local users = 0
    for line in file:lines() do
        user, realm, cipher = parse_line(line)

        if user then
            _M.credentials[user] = {realm= realm, cipher= cipher}
            users = users + 1
        else
            print("[" .. line .. "] invalid: " .. realm)
        end
    end

    file:close()

    if users == 0 then
        return false, "\"user_file\" no valid lines"
    end

    _M.expires = args.expires or 10
    _M.replays = args.replays or 20
    _M.timeout = args.timeout or 60

    -- initialize nonce counter
    math_seed(ngx.time())
    ngx.shared[args.shm]:set("global_counter", math_rand(1, 10000000))

    -- choose a random salt
    local salt, chars = "", "0123456789,.abcdefghijklmnopqrstuvwxyz-=_+!" ..
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for i = 1, 8, 1 do
        local n = math_rand(#chars)
        salt = salt .. str_sub(chars, n, n)
    end

    _M.salt = salt

    return true
end


function _M.challenge(self, stale)
    local nonce = next_nonce(ngx.shared[self.shm], self.salt, self.timeout)
    if not nonce then 
        return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    ngx.header.www_authenticate = tab_concat {
        "Digest",
        " realm=\"", self.realm or "", "\"",
        " domain=\"", self.domain or "", "\"",
        " nonce=\"", nonce, "\"",
        " stale=", stale and "true" or "false",
        " algorithm=MD5",
        " qop=\"auth\""
    }

    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

local function get_value(header, name, quoted)
    local n = header:sub("[, ]" .. name .. "=")
    if not n then return nil end
    
    n = n + 1 + #name + 1  -- 1 for ',' or ' ', 1 for '='
    
    local states = {sw_start= 0, sw_value= 2, sw_done= 3}
    local value_start, value_end
    local state = states.sw_start
    
    for i = n, #header, 1 do
        local c = string.sub(header, i, i)

        if state == states.sw_start then
            if quoted then
                if c == "\"" then
                    state, value_start = states.sw_value, i+1
                else
                    return nil
                end
            else
                state, value_start = states.sw_value, i
            end
            
        elseif state == states.sw_value then
            if quoted then
                if c == "\"" then
                    state, value_end = states.sw_done, i-1
                end
            elseif c == "," then
                state, value_end = states.sw_done, i-1
            elseif i == #header then
                state, value_end = states.sw_done, i
            end
        end
    end
    if state ~= states.sw_done then
        return nil
    end
    
    return header:sub(value_start, value_end)
end


local function get_context(header)
    local prefix = "Digest "
    if str_sub(header, 1, #prefix) ~= prefix then
        return nil
    end

    local ctx = {}

    ctx.user = get_value(header, "username", true)
    ctx.qop = get_value(header, "qop", false)
    ctx.realm = get_value(header, "realm", true)
    ctx.nonce = get_value(header, "nonce", true)
    ctx.nc = get_value(header, "nc", false)
    ctx.uri = get_value(header, "uri", true)
    ctx.cnonce = get_value(header, "cnonce", true)
    ctx.response = get_value(header, "response", true)
    ctx.opaque = get_value(header, "opaque", true)

    -- `opaque` is optional
    if not ctx.user or not ctx.response or not ctx.uri or 
        not ctx.nonce or not realm 
    then
        return nil
    end

    -- if qop exsits, "auth" is the only allowed value for it
    if ctx.qop and (ctx.qop ~= "auth" or not ctx.cnonce or not ctx.nc) 
    then
        return nil
    end

    return ctx
end

-- @return pass or not, stale or not
function _M.verify(self, ctx)
    local cred = self.credentials[user]
    if not cred or cred.realm ~= ctx.realm then
        -- no such user or realm mismatch
        return false, false
    end

    -- verification for "request-digest"
    --
    local ha1, ha2 = cred.cipher, ngx.md5(ngx.req.get_method .. ":" .. ctx.uri)
    local digest 

    if ctx.qop then
        digest = ngx.md5(tab_concat({ha1, ctx.nonce, ctx.nc, ctx.cnonce, 
                                    ctx.qop, ha2}, ":"))
    else
        digest = ngx.md5(tab_concat({ha1, ctx.nonce, ha2}, ":"))
    end

    if digest ~= ctx.response then
        -- RFC 2617: If the request-digest is invalid, then a login failure
        -- should be logged, since repeated login failures from a single client
        -- may indicate an attacker attempting to guess passwords
        print("client from " .. ngx.var.remote_addr .. " request-digest error")
        return false, false
    end

    -- verification for "nonce" 
    --
    local stale = nonce_stale(ngx.shared[self.shm], ctx.nonce, self.timeout, 
                              self.replays, self.expires)
    if stale then
        return false, true
    end

    return true
end


function _M.auth(self)
    -- credentials
    local header = ngx.var.http_authorization
    if not header then 
        return self:challenge(false)
    end

    local ctx = get_context(header)
    if not ctx then
        return ngx.exit(ngx.BAD_REQUEST)  -- suggestion of RFC 2617
    end

    local pass, stale = self:verify(ctx)
    if not pass then
        return self:challenge(stale)
    end

    return ngx.exit(ngx.OK)
end


function _M.new(realm, domain)
    return setmetatable({realm= realm or _M.default_realm, domain= domain}, 
                        {__index= _M})
end


return _M
