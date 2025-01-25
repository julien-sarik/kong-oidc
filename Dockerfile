FROM docker.io/kong/kong-gateway:3.9.0.0-ubuntu

USER root
RUN apt update && apt install -y unzip

COPY plugins/ /plugins
COPY kong-plugin-oidc-1.5.0-1.rockspec /plugins/

WORKDIR /plugins
RUN luarocks make kong-plugin-oidc-1.5.0-1.rockspec

USER kong