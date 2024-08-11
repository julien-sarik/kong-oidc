package = "kong-plugin-custom-request-transformer"
version = "1.0.0-1"
source = {
    url = "git://github.com/julien-sarik/kong-oidc",
    tag = "main",
    dir = "kong-oidc"
}
description = {
    summary = "A Kong plugin to transform request",
    detailed = [[
        Goal of this plugin is to override the priority as dynamic plugin ordering is not available
        in free license (see https://docs.konghq.com/gateway/3.4.x/kong-enterprise/plugin-ordering/)
        so the builtin request-transformer plugin can only be used with the static priority of 801.
    ]],
    homepage = "git://github.com/julien-sarik/kong-oidc"
}
build = {
    type = "builtin",
    modules = {
    ["kong.plugins.custom-request-transformer.handler"] = "kong/plugins/custom-request-transformer/handler.lua",
    ["kong.plugins.custom-request-transformer.schema"] = "kong/plugins/custom-request-transformer/schema.lua"
    }
}
