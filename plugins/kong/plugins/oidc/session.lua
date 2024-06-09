local M = {}

function M.configure(config)
  if config.session_secret then
    local decoded_session_secret = ngx.decode_base64(config.session_secret)
    if not decoded_session_secret then
      kong.log.err("Invalid plugin configuration, session secret could not be decoded")
      return kong.response.error(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    ngx.var.session_secret = decoded_session_secret
  end
end

return M
