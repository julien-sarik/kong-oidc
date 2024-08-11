local Handler = {
    VERSION = "1.0.0",
    -- priority must be bigger than the oidc plugin to fix the logout issue
    PRIORITY = 1001,
}


function Handler:access(config)
    -- remove headers
    for index, headerToRemove in ipairs(config.remove.headers) do
        local headers = ngx.req.get_headers()
        if headers[headerToRemove] then
            headers[headerToRemove] = nil
            kong.service.request.clear_header(headerToRemove)
            ngx.log(ngx.DEBUG, "Removed request header " .. headerToRemove .. " from path " .. kong.request.get_path())
        end
      end
end

return Handler