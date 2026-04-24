package com.tailosoft.keycloak;

import jakarta.ws.rs.core.MultivaluedMap;
import java.util.ArrayList;
import java.util.List;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;

/**
 * OIDC protocol mapper that lets a master-realm admin impersonate a tenant-realm user by
 * presenting a short-lived code pre-provisioned on that target user's Keycloak attributes.
 *
 * <p>At the token endpoint, the mapper reads three form parameters from the POST body:
 * <ul>
 *   <li>{@code target_realm} — slug of the tenant realm to impersonate into.</li>
 *   <li>{@code target_user_id} — id of the user in that realm.</li>
 *   <li>{@code impersonate_code} — the one-time code.</li>
 * </ul>
 *
 * <p>The mapper looks up the target user, reads the {@code impersonate_code} and
 * {@code impersonate_expiry} attributes (names configurable), and — if the code matches and the
 * expiry is in the future — injects {@code resource_access["{target_realm}-realm"].roles =
 * ["impersonation"]} into the access token, then deletes both attributes (single-use).
 *
 * <p>If any check fails the token is returned untouched; the downstream admin-API call will then
 * fail with 403 naturally. No information leak about which check failed.
 *
 * <p>Intended to be attached to an <em>optional</em> client scope so everyday tokens are
 * unaffected. The frontend activates it only at impersonation time:
 * <pre>
 *   POST /realms/master/protocol/openid-connect/token
 *   grant_type=refresh_token&amp;client_id=web_app&amp;refresh_token=...
 *   scope=openid &lt;custom-scope-with-this-mapper&gt;
 *   target_realm=&lt;slug&gt;
 *   target_user_id=&lt;user-id&gt;
 *   impersonate_code=&lt;code&gt;
 * </pre>
 */
public class CrossRealmImpersonationMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper {

    public static final String PROVIDER_ID = "tailosoft-cross-realm-impersonation-mapper";
    public static final String IMPERSONATION_ROLE = "impersonation";

    public static final String CFG_CODE_ATTRIBUTE = "codeAttributeName";
    public static final String CFG_EXPIRY_ATTRIBUTE = "expiryAttributeName";
    public static final String CFG_TARGET_REALM_PARAM = "targetRealmParam";
    public static final String CFG_TARGET_USER_PARAM = "targetUserParam";
    public static final String CFG_CODE_PARAM = "codeParam";
    public static final String CFG_REQUIRED_REALM_ROLE = "requiredRealmRole";

    private static final String DEF_CODE_ATTRIBUTE = "impersonate_code";
    private static final String DEF_EXPIRY_ATTRIBUTE = "impersonate_expiry";
    private static final String DEF_TARGET_REALM_PARAM = "target_realm";
    private static final String DEF_TARGET_USER_PARAM = "target_user_id";
    private static final String DEF_CODE_PARAM = "impersonate_code";

    private static final List<ProviderConfigProperty> CONFIG;

    static {
        CONFIG = new ArrayList<>();
        CONFIG.add(stringProp(CFG_CODE_ATTRIBUTE, "Code attribute name",
                "User attribute holding the one-time code", DEF_CODE_ATTRIBUTE));
        CONFIG.add(stringProp(CFG_EXPIRY_ATTRIBUTE, "Expiry attribute name",
                "User attribute holding the code's expiry (epoch-ms)", DEF_EXPIRY_ATTRIBUTE));
        CONFIG.add(stringProp(CFG_TARGET_REALM_PARAM, "target_realm form-param name",
                "Name of the form parameter carrying the target realm slug", DEF_TARGET_REALM_PARAM));
        CONFIG.add(stringProp(CFG_TARGET_USER_PARAM, "target_user_id form-param name",
                "Name of the form parameter carrying the target user id", DEF_TARGET_USER_PARAM));
        CONFIG.add(stringProp(CFG_CODE_PARAM, "code form-param name",
                "Name of the form parameter carrying the one-time code", DEF_CODE_PARAM));
        CONFIG.add(stringProp(CFG_REQUIRED_REALM_ROLE, "Required realm role",
                "If set, the caller must hold this realm role (defense-in-depth). Leave empty to disable.", ""));
    }

    private static ProviderConfigProperty stringProp(String name, String label, String help, String defaultValue) {
        ProviderConfigProperty p = new ProviderConfigProperty();
        p.setName(name);
        p.setLabel(label);
        p.setHelpText(help);
        p.setType(ProviderConfigProperty.STRING_TYPE);
        p.setDefaultValue(defaultValue);
        return p;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Cross-Realm Impersonation (code)";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Consumes a one-time code pre-provisioned on a target user's attributes and "
                + "injects resource_access.{target_realm}-realm.roles=[impersonation] into the "
                + "access token. Single-use: both code and expiry attributes are cleared on match.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG;
    }

    @Override
    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel,
                                            KeycloakSession session, UserSessionModel userSession,
                                            ClientSessionContext clientSessionCtx) {
        if (session.getContext().getHttpRequest() == null) {
            return token;
        }
        MultivaluedMap<String, String> params = session.getContext().getHttpRequest().getDecodedFormParameters();
        if (params == null) {
            return token;
        }

        String targetRealmSlug = params.getFirst(cfg(mappingModel, CFG_TARGET_REALM_PARAM, DEF_TARGET_REALM_PARAM));
        String targetUserId = params.getFirst(cfg(mappingModel, CFG_TARGET_USER_PARAM, DEF_TARGET_USER_PARAM));
        String presentedCode = params.getFirst(cfg(mappingModel, CFG_CODE_PARAM, DEF_CODE_PARAM));
        if (isBlank(targetRealmSlug) || isBlank(targetUserId) || isBlank(presentedCode)) {
            return token;
        }

        String requiredRole = cfg(mappingModel, CFG_REQUIRED_REALM_ROLE, "");
        if (!requiredRole.isEmpty()) {
            RoleModel role = session.getContext().getRealm().getRole(requiredRole);
            if (role == null || !userSession.getUser().hasRole(role)) {
                return token;
            }
        }

        RealmModel targetRealm = session.realms().getRealmByName(targetRealmSlug);
        if (targetRealm == null) {
            return token;
        }
        UserModel targetUser = session.users().getUserById(targetRealm, targetUserId);
        if (targetUser == null) {
            return token;
        }

        String codeAttr = cfg(mappingModel, CFG_CODE_ATTRIBUTE, DEF_CODE_ATTRIBUTE);
        String expiryAttr = cfg(mappingModel, CFG_EXPIRY_ATTRIBUTE, DEF_EXPIRY_ATTRIBUTE);
        String storedCode = targetUser.getFirstAttribute(codeAttr);
        String storedExpiry = targetUser.getFirstAttribute(expiryAttr);
        if (isBlank(storedCode) || isBlank(storedExpiry) || !storedCode.equals(presentedCode)) {
            return token;
        }
        long expiryMs;
        try {
            expiryMs = Long.parseLong(storedExpiry);
        } catch (NumberFormatException e) {
            return token;
        }
        if (System.currentTimeMillis() >= expiryMs) {
            return token;
        }

        String clientId = targetRealmSlug + "-realm";
        ClientModel managementClient = session.getContext().getRealm().getClientByClientId(clientId);
        if (managementClient == null) {
            return token;
        }

        token.addAccess(clientId).addRole(IMPERSONATION_ROLE);
        targetUser.removeAttribute(codeAttr);
        targetUser.removeAttribute(expiryAttr);
        return token;
    }

    private static String cfg(ProtocolMapperModel mapper, String key, String fallback) {
        String v = mapper.getConfig().get(key);
        return isBlank(v) ? fallback : v;
    }

    private static boolean isBlank(String s) {
        return s == null || s.isEmpty();
    }
}