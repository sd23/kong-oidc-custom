local BasePlugin = require "kong.plugins.base_plugin"
local OidcHandler = BasePlugin:extend()
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")

OidcHandler.PRIORITY = 1000


function OidcHandler:new()
  OidcHandler.super.new(self, "oidc")
end

function OidcHandler:access(config)
  OidcHandler.super.access(self)
  local oidcConfig = utils.get_options(config, ngx)

  if filter.shouldProcessRequest(oidcConfig) then
    kong.log("entered access")
    kong.log.debug("entered access with info"," here")
    session.configure(config)
    handle(oidcConfig)
  else
    ngx.log(ngx.DEBUG, "OidcHandler ignoring request, path: " .. ngx.var.request_uri)
  end

  ngx.log(ngx.DEBUG, "OidcHandler done")
end

function handle(oidcConfig)
  local response
  if oidcConfig.introspection_endpoint then
    response = introspect(oidcConfig)
    if response then
      utils.injectUser(response)
    end
  end

  if response == nil then
    response = make_oidc(oidcConfig)
    kong.log("\nreturned response from make_oidc" , response)
    if response then
      if (response.user) then
        utils.injectUser(response.user)
      end
      if (response.access_token) then
        utils.injectAccessToken(response.access_token)
        -- kong.log("Injecting authorization header" .. response.access_token)
        -- utils.injectAuthHeader(response.access_token)
      end
      if (response.id_token) then
        utils.injectIDToken(response.id_token)
      end
    end
  end
  kong.log("\ncalling authenticate fn with info log ")
  -- authenticate(oidcConfig)
end

function make_oidc(oidcConfig)
  ngx.log(ngx.DEBUG, "OidcHandler calling authenticate, requested path: " .. ngx.var.request_uri)
  local res, err = require("resty.openidc").authenticate(oidcConfig)
  kong.log("\nresponse in make_oidc" , res)
  if err then
    if oidcConfig.recovery_page_path then
      ngx.log(ngx.DEBUG, "Entering recovery page: " .. oidcConfig.recovery_page_path)
      ngx.redirect(oidcConfig.recovery_page_path)
    end
    utils.exit(500, err, ngx.HTTP_INTERNAL_SERVER_ERROR)
  end
  return res
end

function introspect(oidcConfig)
  if utils.has_bearer_access_token() or oidcConfig.bearer_only == "yes" then
    local res, err = require("resty.openidc").introspect(oidcConfig)
    kong.log("\nerr in introspect = ",err)
    kong.log("\nres in introspect = ",res)
    if err then
      if oidcConfig.bearer_only == "yes" then
        kong.log("\nin instrospect oidcConfig.realm = ",oidcConfig.realm)
        ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",error="' .. err .. '"'
        utils.exit(ngx.HTTP_UNAUTHORIZED, err, ngx.HTTP_UNAUTHORIZED)
      end
      return nil
    end
    kong.log("\nOidcHandler introspect succeeded, requested path: " .. ngx.var.request_uri)
    ngx.log(ngx.DEBUG, "OidcHandler introspect succeeded, requested path: " .. ngx.var.request_uri)
    return res
  end
  return nil
end

-- function authenticate(oidcConfig)
--     -- call introspect for OAuth 2.0 Bearer Access Token validation
--     local opts = {
--         discovery = oidcConfig.discovery,
--         client_id = oidcConfig.client_id,
--         client_secret = oidcConfig.client_secret,
--         logout_path = oidcConfig.logout_path,
--         session_contents = {id_token=true,enc_id_token=true,user=true,access_token=true}
--       }
--     local res, err, target, session = require("resty.openidc").authenticate(opts)
--     kong.log("\ninside authenticate fn res = ", res, "error = ", err)
--     if err then
--       ngx.status = 403
--       ngx.say(err)
--       ngx.exit(ngx.HTTP_FORBIDDEN)
--     end
--     local parsed_token, token_err = require("resty.openidc").jwt_verify(res.access_token, opts)
--     if token_err then
--       ngx.log(ngx.DEBUG, "access token is not a valid JWT")
--       ngx.exit(ngx.HTTP_FORBIDDEN)
--     end
--     local cjson = require "cjson"
--     -- ngx.req.set_header("Authorization", "Bearer " .. cjson.encode(parsed_token))
--     ngx.req.set_header("Authorization", "Bearer " .. res.access_token)
--     kong.service.request.set_header("Authorization","Bearer " .. res.access_token)
--     kong.log(ngx.req.get)
--     kong.log("res.access_token", res.access_token)
--     kong.log(kong.request.get_headers())
--     kong.log(kong.service.response.get_headers())
--     ngx.req.clear_header("Cookie")
--     ngx.log(ngx.DEBUG, "cookie to token converted " .. type(res.access_token) .."\ntoken: " .. res.access_token)
--     kong.log("-----------------------.. used cookie to token converted " .. type(res.access_token) .."\ntoken: " .. res.access_token)
--     kong.log("cookie to token converted ",type(res.access_token), "\ntoken: ", res.access_token)
-- end
return OidcHandler
