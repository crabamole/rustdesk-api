#!/bin/bash
# Copyright 2024 Ronan LE MEILLAT for SCTG Development
cargo run -q -- openapi >webconsole/src/api/openapi.json &&
    docker run --rm -v ${PWD}:/local swaggerapi/swagger-codegen-cli-v3 generate -i file:///local/webconsole/src/api/openapi.json --additional-properties modelPropertyNaming=snake_case -l typescript-axios -o /local/webconsole/src/api &&
    sed -ibak -e 's/confirm_password/\"confirm-password\"/' webconsole/src/api/models/add-user-request.ts &&
    sed -ibak -e 's/confirm_password/\"confirm-password\"/' webconsole/src/api/models/update-user-request.ts &&
    sed -ibak -e 's/device_info/\"deviceInfo\"/' webconsole/src/api/models/oidc-auth-request.ts &&
    rm webconsole/src/api/models/*tsbak
