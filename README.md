# ✨ Wiz Gadget - Webhook ✨

## Configuration
The following table list the available environment variables.

|             ENVIRONMENT VARIABLE                    |   REQUIRED   |          DESCRIPTION                                  |
|-----------------------------------------------------|--------------|-------------------------------------------------------|
| BASIC_AUTH_USERNAME                                 | Optional     | Basic Authentication Username                         |
| BASIC_AUTH_PASSWORD                                 | Optional     | Basic Authentication Password                         |
| TOKEN_AUTH                                          | Yes          | Token Authentication                                  |
| OAUTH_CLIENT_ID                                     | Yes          | Client ID for Wiz Service Account                     |
| OAUTH_CLIENT_SECRET                                 | Yes          | Client Secret for Wiz Service Account                 |
| OAUTH_AUTH_URL                                      | Yes          | Wiz Authentication URL                                |
| API_URL                                             | Yes          | Wiz API URL                                           |
| IP_WHITELIST                                        | Yes          | List of IP Addresses to add to whitelist              |

### Authentication
The Wiz Gadget supports either Basic and Token authentication.

### IP Whitelist
The Wiz Gadget MUST be configured with an IP Whitelist.

## Webhook SSL Certificate
The Wiz Gadget requires SSL Certificate to be provided.

- Server Certificate should be mounted: `-v ./certificates/server.crt:/app/server.crt`
- Server Key should be mounted: `-v ./certificates/server.key:/app/server.key`

## Deployment Options
### Using Docker
``` console
docker run --name wiz-gadget -d \
-e TOKEN_AUTH=<TOKEN_AUTH> \
-e OAUTH_CLIENT_ID=<OAUTH_CLIENT_ID> \
-e OAUTH_CLIENT_SECRET=<OAUTH_CLIENT_ID> \
-e OAUTH_AUTH_URL=https://auth.app.wiz.io/oauth/token \
-e API_URL=https://api.us20.app.wiz.io/graphql \
-e IP_WHITELIST=3.22.160.14,52.15.228.9,3.21.88.133 \
-v ./certificates/server.crt:/app/server.crt \
-v ./certificates/server.key:/app/server.key \
-p 8181:8181 \
danielmoloney/wiz-gadget:v1.0.0
```