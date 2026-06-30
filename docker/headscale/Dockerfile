# syntax=docker/dockerfile:1
#
# Headscale with the test config + allow-all policy baked in, so the harness
# needs no bind mount (the repo path isn't Docker-bind-mountable). Build with the
# repo root as context:
#
#   docker build -f docker/headscale/Dockerfile -t ts-headscale-e2e .
FROM headscale/headscale:0.26.1
COPY docker/headscale/config.yaml /etc/headscale/config.yaml
COPY docker/headscale/policy.json /etc/headscale/policy.json
