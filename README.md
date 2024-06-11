# kong-oidc
## description
This plugin was initially started by a [Nokia open-source project](https://github.com/nokia/kong-oidc). Since the initial project has being supported in 2019, it has been forked in 2021 by [another repo](https://github.com/revomatico/kong-oidc) which archived since 2024.  
The plugin relies on the Nginx [lua-resty-openidc library](https://github.com/zmartzone/lua-resty-openidc).

## build & run
Build Kong image embedded with the OIDC plugin
```
podman build -t kong:kong-oidc .
```

Create podman network
```
podman network create foo
```

Spin up Kong, Keycloak and a HTTP mock assuming the role of a front-end
```
podman play kube pods.yml --net foo
```

Import an OIDC client from `keycloak-client.json` file in keycloak running on `http://localhost:8080/admin/master/console/#/master/clients`.  

Configure the HTTP mock to return headers proxied by Kong. The mock will return the headers forwarded by Kong.
```
curl -v -X PUT "http://localhost:1080/mockserver/expectation" -d '{
    "httpRequest": {
        "path": "/"
    },
    "httpResponseTemplate": {
        "template": "{ \"statusCode\": 200, \"body\": \"$!request.headers\" }",
        "templateType": "VELOCITY"
    }
}'
```

Browse the resource server at:
```
http://localhost:8000/some/path
```

Shutdown
```
podman play kube pods.yml --down
```

Github of the Kong OIDC fork https://github.com/revomatico/kong-oidc

# troubleshooting
## `request to the redirect_uri path, but there's no session state found`
This error is raised when the plugin fails to get the session from the cookie.  
There are multiple causes for this issue:
- misconfigured redirect URI: if the configured redirect URI is not specific enough (i.e. the same as the route exposed by Kong), the user will hit this endpoint directly (before being redirected to the authorization server) and before having receive any cookie. Then Kong OIDC plugin consider it has to perform a code exchange and fail trying to identify the session.
- inconsistent scheme: if the flow is initiated over HTTP but the redirect URI is using HTTPS then the cookie won't be sent to the redirect URI endpoint.
- session secret: if not set, a default secret is generated by the Kong workers leading to different secrets being used and workers unable to decrypt the session encrypted by another worker.
- `SameSite` cookie attribute: the session cookie used by the Kong OIDC plugin should be set to `Lax` or `None` so that it's set even if the user land in the endpoint from a link
- header limit: since the cookie contains access/ID/refresh tokens it might be truncate if there is reverse proxy in front of Kong
