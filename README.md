

Example Usage
-------------

    lua_shared_dict nonce 2m;

    init_by_lua '
        local auth = require("resty.auth")

        local ok, msg = auth.setup {
            scheme= "digest", 
            shm= "nonce", 
            user_file= "htdigest",
            expires= 10,
            replays= 5,
            timeout= 10,
        }
        if not ok then error(msg) end

        local ok, msg = auth.setup {
            scheme= "basic", 
            user_file= "htpasswd"
        )
        if not ok then print msg end
    ';

    server {
        location /auth_basic/ {
            access_by_lua '
                local auth = require("resty.auth")
                auth.new("basic"):auth("my site")
            ';
        }

        location /auth_digest/ {
            access_by_lua '
                local auth = require("resty.auth")
                auth.new("digest"):auth("my site2")
            ';
        }
    }
