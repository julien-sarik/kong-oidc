FROM docker.io/library/kong:3.3.1-alpine

COPY plugins/ /plugins
COPY kong-plugin-oidc-1.4.0-1.rockspec kong-plugin-custom-request-transformer-1.0.0-1.rockspec /plugins/

WORKDIR /plugins

USER root

# remove pre-installed resty-session library as it's not compatible with the one required by resty-openidc
# https://github.com/revomatico/kong-oidc/issues/34#issuecomment-1594473267
RUN luarocks remove lua-resty-session 4.0.3-1 --force
RUN luarocks make kong-plugin-oidc-1.4.0-1.rockspec

RUN luarocks make kong-plugin-custom-request-transformer-1.0.0-1.rockspec

USER kong