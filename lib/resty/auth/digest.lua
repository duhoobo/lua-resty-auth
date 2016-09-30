local math_seed = math.randomseed
local math_rand = math.random
local tab_concat = table.concat


local _M = {
    shm= nil,
    expires= nil,
    replays= nil,
    timeout= nil,
    salt= nil,
    credentials= {},
}


local function get_value(header, name, quoted)
    local n = header:find("[, ]" .. name .. "=")
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
    if header:sub(1, #prefix) ~= prefix then
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
        not ctx.nonce or not ctx.realm
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


local function next_nonce(shared_dict, salt, timeout, expires)
    local ok, gc, err, now, forcible, nonce

    gc, err = shared_dict:incr("global_counter", 1)
    now = ngx.time()

    nonce = ngx.encode_base64(ngx.hmac_sha1(salt, now .. ":" .. gc))

    ok, err, forcible = shared_dict:set(nonce, 0, now + timeout, now + expires)
    if not ok then
        return nil, err
    end

    return nonce
end


-- nonce stale or not
local function nonce_stale(shared_dict, nonce, replays)
    local nc, err = shared_dict:incr(nonce, 1)
    if not nc or nc > replays then  -- already evicted or overused
        return true
    end

    local val, expires_at = shared_dict:get(nonce)
    if not val then  -- already evicted
        return true
    end

    if expires_at <= ngx.now() then
        shared_dict:delete(nonce)
        return true
    end

    -- not expires and not overused
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
            print(user, realm, cipher)
            users = users + 1
        else
            print("[" .. line .. "] invalid: " .. realm)
        end
    end

    file:close()

    if users == 0 then
        return false, "\"user_file\" no valid lines"
    end

    -- Once a digest challenge has been successfully answered by the client,
    -- subsequent requests will attempt to re-use the 'nonce' value from the
    -- original challenge. To complicate MitM attacks, it's best to limit the
    -- duration a cached nonce will be accepted.
    _M.expires = args.expires or 10
    -- Nonce re-use should also be limited to a fixed number of requests.
    _M.replays = args.replays or 20
    -- When a client first requests a protected page, the server returns a 401
    -- status code along with a challenge in the __WWW-Authenticate__ header.
    -- At this point most browsers will present a dialog box to the user
    -- prompting them to log in. `timeout` defines how long challenges will
    -- remain valid. If the user waits longer than this time before submitting
    -- their name and password, the challenge will be considered `stale` and
    -- they will be prompted to log in again.
    _M.timeout = args.timeout or 60

    -- initialize nonce counter
    math_seed(ngx.time())
    ngx.shared[args.shm]:set("global_counter", math_rand(1, 10000000))

    -- generate a random salt to encrypt nonce
    local salt, chars = "", "0123456789,.abcdefghijklmnopqrstuvwxyz-=_+!" ..
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for i = 1, 8, 1 do
        local n = math_rand(#chars)
        salt = salt .. chars:sub(n, n)
    end
    _M.salt = salt

    return true
end


function _M.challenge(self, stale)
    local nonce = next_nonce(ngx.shared[self.shm], self.salt, self.timeout,
                             self.expires)
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


-- @return pass or not, stale or not
function _M.verify(self, ctx)
    local cred = self.credentials[ctx.user]
    if not cred or cred.realm ~= ctx.realm then
        -- no such user or realm mismatch
        return false, false
    end

    -- verification for "request-digest"
    --
    local ha1, ha2 = cred.cipher, ngx.md5(tab_concat({ngx.req.get_method(),
                                                     ctx.uri}, ":"))
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
    local stale = nonce_stale(ngx.shared[self.shm], ctx.nonce, self.replays)
    if stale then
        return false, true
    end

    return true
end


function _M.auth(self)
    local header = ngx.var.http_authorization
    if not header then
        return self:challenge(false)
    end

    local ctx = get_context(header)
    if not ctx then
        return ngx.exit(ngx.HTTP_BAD_REQUEST)  -- suggestion of RFC 2617
    end

    local pass, stale = self:verify(ctx)
    if not pass then
        return self:challenge(stale)
    end

    return ngx.exit(ngx.OK)
end


function _M.new(realm, domain)
    return setmetatable({realm= realm, domain= domain}, {__index= _M})
end


return _M
