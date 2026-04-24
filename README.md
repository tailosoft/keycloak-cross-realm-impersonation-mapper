# keycloak-cross-realm-impersonation-mapper

A Keycloak OIDC protocol mapper that enables **cross-realm impersonation** via a short-lived, single-use code — without inflating every-day tokens and without O(N-tenants) role-binding fan-out.

## The problem

On a Keycloak server running multiple realms, an admin sitting in realm **A** (typically `master`) can impersonate users in realm **B** by POSTing to the admin API:

```
POST {kc}/admin/realms/{B}/users/{userId}/impersonation
```

To authorize the call, the caller's access token must carry the `impersonation` client role on the `{B}-realm` management client in realm A. The naive way to get it in the token is turning on the default `roles` scope on the admin SPA — which dumps per-client roles for **every** realm into `resource_access`, breaking once you have hundreds of realms. The obvious workaround — pre-granting the `impersonation` client role directly to each authorized admin on every tenant realm — scales O(users × realms) and creates a coordination problem every time a tenant is added or a user's scope changes.

## The fix

Flip authorization from "pre-provisioned role bindings" to "short-lived code redemption":

1. Your application (e.g. an admin backend) decides if a given admin is allowed to impersonate a given user in a given realm.
2. It generates a short code (6 chars, 5 min expiry — conventions, not enforced), writes it onto the **target user's** Keycloak attributes.
3. The admin frontend POSTs to `/token` with `target_realm`, `target_user_id`, and the code.
4. This mapper, attached to an **optional** client scope on the caller's client, validates the code against the target user's attributes. If valid and unexpired, it injects `resource_access["{target_realm}-realm"].roles = ["impersonation"]` into the returned access token and **deletes the code** (single-use).
5. The admin then calls the admin impersonation endpoint with that token.

The authorization decision lives in **your** application — the mapper is just a verifier of "this code exists on the user and is fresh". Three wins:

- **O(1) per click.** No per-user-per-tenant role-binding fan-out. Whether you have 10 tenants or 100,000, the cost is constant.
- **Consent-ready.** Same mapper supports a future "user generates the code and hands it to support" flow without any library changes.
- **Narrow token.** The issued token is 1 KB regardless of realm count — only one `resource_access` entry.

## How it works

At the OIDC token endpoint, the mapper reads these form parameters from the POST body:

| Parameter | Default | Description |
|---|---|---|
| `target_realm` | configurable | Slug of the realm to impersonate into. |
| `target_user_id` | configurable | ID of the user in that realm. |
| `impersonate_code` | configurable | The one-time code. |

It then:

1. Looks up the user in the target realm.
2. Reads their `impersonate_code` and `impersonate_expiry` attributes.
3. Verifies: code matches, `expiry > now`.
4. On match: adds `resource_access["{target_realm}-realm"].roles = ["impersonation"]` to the access token, then removes both attributes.
5. On any mismatch: returns the token untouched (no leak about which check failed).

Provider id: `tailosoft-cross-realm-impersonation-mapper`.

## Install

### 1. Drop the JAR into Keycloak's providers directory

Grab the latest JAR from [Maven Central](https://central.sonatype.com/artifact/com.tailosoft/keycloak-cross-realm-impersonation-mapper) or [Releases](https://github.com/tailosoft/keycloak-cross-realm-impersonation-mapper/releases) and put it in `/opt/keycloak/providers/`.

Dockerfile:

```dockerfile
FROM curlimages/curl:8.8.0 AS mapper
ARG MAPPER_VERSION=1.1.0
RUN curl -fsSL https://repo1.maven.org/maven2/com/tailosoft/keycloak-cross-realm-impersonation-mapper/${MAPPER_VERSION}/keycloak-cross-realm-impersonation-mapper-${MAPPER_VERSION}.jar \
  -o /tmp/mapper.jar

FROM quay.io/keycloak/keycloak:26.0.8
COPY --from=mapper /tmp/mapper.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build
```

### 2. Register the mapper on an optional client scope

Create an optional client scope, add the `Cross-Realm Impersonation (code)` mapper, and attach the scope to your admin client as **Optional**. Via REST:

```bash
# Scope
curl -X POST $KC/admin/realms/master/client-scopes -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "name": "impersonate",
    "protocol": "openid-connect",
    "attributes": { "include.in.token.scope": "false", "display.on.consent.screen": "false" }
  }'

# Mapper on the scope
SCOPE_ID=$(curl -s $KC/admin/realms/master/client-scopes -H "Authorization: Bearer $TOKEN" \
  | jq -r '.[] | select(.name=="impersonate") | .id')
curl -X POST "$KC/admin/realms/master/client-scopes/$SCOPE_ID/protocol-mappers/models" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{
    "name": "impersonate",
    "protocol": "openid-connect",
    "protocolMapper": "tailosoft-cross-realm-impersonation-mapper",
    "config": {}
  }'

# Attach scope to the admin client (web_app) as Optional
CLIENT_ID=$(curl -s "$KC/admin/realms/master/clients?clientId=web_app" -H "Authorization: Bearer $TOKEN" \
  | jq -r '.[0].id')
curl -X PUT "$KC/admin/realms/master/clients/$CLIENT_ID/optional-client-scopes/$SCOPE_ID" \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Implement code issuance server-side

Whoever authorizes impersonation (typically your backend) generates a code, writes it onto the target user's Keycloak attributes. Pseudo:

```java
String code = randomBase36(6);                 // e.g. "K7H9X2"
long expiryMs = System.currentTimeMillis() + Duration.ofMinutes(5).toMillis();
UserRepresentation u = kc.realm(targetRealm).users().get(targetUserId).toRepresentation();
u.singleAttribute("impersonate_code", code);
u.singleAttribute("impersonate_expiry", String.valueOf(expiryMs));
kc.realm(targetRealm).users().get(targetUserId).update(u);
return new CodeResponse(code, expiryMs);
```

Return the code to the admin; they use it in step 4.

### 4. Redeem the code from the frontend

```ts
// Step 1: ask your backend for a code (your backend does the policy check + writes attributes)
const { code } = await fetch('/api/impersonation-codes', {
  method: 'POST',
  body: JSON.stringify({ realm, userId }),
}).then(r => r.json());

// Step 2: exchange refresh token for a narrow access token carrying the impersonation role
const tokenResp = await fetch(`${kc}/realms/master/protocol/openid-connect/token`, {
  method: 'POST',
  body: new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: 'web_app',
    refresh_token,
    scope: 'openid impersonate',
    target_realm: realm,
    target_user_id: userId,
    impersonate_code: code,
  }),
}).then(r => r.json());

// Step 3: call the admin impersonation endpoint
await fetch(`${kc}/admin/realms/${realm}/users/${userId}/impersonation`, {
  method: 'POST',
  credentials: 'include',
  headers: { Authorization: `Bearer ${tokenResp.access_token}`, 'Content-Type': 'application/json' },
});
```

Keycloak sets `KEYCLOAK_IDENTITY` on its origin (hence `credentials: 'include'`); redirect the browser to the target realm's app origin and OIDC picks up the impersonated session.

## Configuration

All mapper config keys default to sensible values. Override via the `config` block when creating the mapper.

| Key | Default | Purpose |
|---|---|---|
| `codeAttributeName` | `impersonate_code` | Attribute on the target user holding the code |
| `expiryAttributeName` | `impersonate_expiry` | Attribute holding the expiry (epoch ms) |
| `targetRealmParam` | `target_realm` | Form-param name for the target realm |
| `targetUserParam` | `target_user_id` | Form-param name for the target user id |
| `codeParam` | `impersonate_code` | Form-param name for the code |
| `requiredRealmRole` | *(empty)* | If set, caller must hold this realm role too (belt-and-suspenders) |

## Security notes

- **The code is a one-time capability.** Both attributes are cleared on successful redemption. Losing it after use is harmless.
- **Short TTL is your primary defense.** 5 minutes is a reasonable default; shorter if your UX permits.
- **Keep the scope Optional.** Default scopes run the mapper on every token issuance; Optional only runs when requested. Keeps the happy path zero-cost.
- **Your app owns authorization.** The mapper does not evaluate "is this admin allowed to impersonate that user" — it only verifies code presence. Do the policy check server-side *before* writing the code.
- **Transport.** Always HTTPS. The code is sensitive within its short validity window.
- **Concurrent requests for the same target user race on the attribute.** If two admins try to generate a code for the same user simultaneously, the second generation overwrites the first — the first admin's click fails gracefully and they re-request. Acceptable for virtually all real-world deployments.

## Build from source

```bash
mvn package
# -> target/keycloak-cross-realm-impersonation-mapper-<version>.jar
```

Requires JDK 17+ and Maven 3.9+.

## Compatibility

Built and tested against Keycloak **26.0.8**. The `AbstractOIDCProtocolMapper` / `OIDCAccessTokenMapper` interfaces are stable across the 24.x–26.x line; bumping the `keycloak.version` property should be enough for other versions in that range.

## License

Apache 2.0.
