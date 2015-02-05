lua-resty-auth
==============

A Lua resty module for HTTP Authentication (both basic and digest scheme
supported, referring to [RFC 2617](http://www.ietf.org/rfc/rfc2617.txt)).



TODO
----

* md5crpyt for scheme __basic__
* crypt for scheme __basic__
* test case
* stress test
* security audit



Missing Features
----------------

* qop option `auth-int`
* algorithm `MD5-sess`



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
                auth.new("basic", "you@site"):auth()
            ';
        }

        location /auth_digest/ {
            access_by_lua '
                local auth = require("resty.auth")
                auth.new("digest", "you@site"):auth()
            ';
        }
    }



Thanks
------


* The idea and some of the code are borrowed from [here](http://www.pppei.net/blog/post/663)
* The module parameters mimic the directives of [ngx_http_auth_digest](http://wiki.nginx.org/HttpAuthDigestModule)
