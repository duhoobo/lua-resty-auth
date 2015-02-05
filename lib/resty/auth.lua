local submodules = {
    basic=  require("resty.auth.basic"),
    digest= require("resty.auth.digest")
}


local _M = {}
_M._VERSION = "0.0.1"


function _M.setup(args)
    if not args.scheme then
        return nil, "\"scheme\" needed"

    elseif not submodules[args.scheme] then
        return nil, "scheme \"" .. args.scheme .. "\" not supported"
    end

    return submodules[args.scheme].setup(args)
end


function _M.new(scheme, ...)
    if not scheme or not submodules[scheme] then
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
        
    return submodules[scheme].new(...)
end


return _M
