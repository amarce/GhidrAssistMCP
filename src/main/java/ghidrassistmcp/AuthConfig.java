package ghidrassistmcp;

import ghidra.framework.preferences.Preferences;

/**
 * Centralized auth configuration helpers covering none/basic/oauth modes.
 */
public final class AuthConfig {

    private static final String SETTINGS_CATEGORY = "GhidrAssistMCP";

    public static final String AUTH_MODE_SETTING = "Auth Mode";
    public static final String BASIC_USERNAME_SETTING = "Basic Auth Username";
    public static final String BASIC_PASSWORD_SETTING = "Basic Auth Password";
    public static final String BASIC_PASSWORD_HASH_SETTING = "Basic Auth Password Hash";

    public static final String OAUTH_ISSUER_SETTING = "OAuth Issuer";
    public static final String OAUTH_JWKS_URL_SETTING = "OAuth JWKS URL";
    public static final String OAUTH_AUDIENCE_SETTING = "OAuth Audience";
    public static final String OAUTH_REQUIRED_SCOPE_SETTING = "OAuth Required Scope";

    // Legacy settings kept for backwards compatibility with existing preferences.
    public static final String OAUTH_CLIENT_ID_SETTING = "OAuth Client Id";
    public static final String OAUTH_BEARER_TOKEN_SETTING = "OAuth Bearer Token";
    public static final String OAUTH_BEARER_TOKEN_HASH_SETTING = "OAuth Bearer Token Hash";

    public static final String DEFAULT_BASIC_USERNAME = "mcp";

    public enum AuthMode {
        NONE("none"),
        BASIC("basic"),
        OAUTH("oauth");

        private final String persistedValue;

        AuthMode(String persistedValue) {
            this.persistedValue = persistedValue;
        }

        public String persistedValue() {
            return persistedValue;
        }

        public static AuthMode fromPersisted(String value) {
            if (value != null) {
                for (AuthMode mode : values()) {
                    if (mode.persistedValue.equalsIgnoreCase(value)) {
                        return mode;
                    }
                }
            }
            return NONE;
        }
    }

    private AuthConfig() {
    }

    public static String getQualifiedKey(String setting) {
        return SETTINGS_CATEGORY + "." + setting;
    }

    public static String resolveBasicPasswordHash() {
        String hash = Preferences.getProperty(getQualifiedKey(BASIC_PASSWORD_HASH_SETTING), "");
        if (PasswordVerifier.isHashedPassword(hash)) {
            return hash;
        }
        return "";
    }

    public static String chooseHashForSave(String enteredSecret, String existingHash) {
        if (enteredSecret != null && !enteredSecret.isEmpty()) {
            return PasswordVerifier.hashPassword(enteredSecret);
        }
        return existingHash != null ? existingHash : "";
    }

    public static String resolveOauthTokenHash() {
        String hash = Preferences.getProperty(getQualifiedKey(OAUTH_BEARER_TOKEN_HASH_SETTING), "");
        if (PasswordVerifier.isHashedPassword(hash)) {
            return hash;
        }
        return "";
    }

    public static void persistAuthSettings(AuthMode mode,
                                           String basicUsername,
                                           String basicPasswordHash,
                                           String oauthIssuer,
                                           String oauthJwksUrl,
                                           String oauthAudience,
                                           String oauthRequiredScope,
                                           String oauthClientId,
                                           String oauthTokenHash) {
        Preferences.setProperty(getQualifiedKey(AUTH_MODE_SETTING), mode.persistedValue());
        Preferences.setProperty(getQualifiedKey(BASIC_USERNAME_SETTING), basicUsername != null ? basicUsername : "");
        Preferences.setProperty(getQualifiedKey(BASIC_PASSWORD_HASH_SETTING), basicPasswordHash != null ? basicPasswordHash : "");
        Preferences.setProperty(getQualifiedKey(OAUTH_ISSUER_SETTING), oauthIssuer != null ? oauthIssuer : "");
        Preferences.setProperty(getQualifiedKey(OAUTH_JWKS_URL_SETTING), oauthJwksUrl != null ? oauthJwksUrl : "");
        Preferences.setProperty(getQualifiedKey(OAUTH_AUDIENCE_SETTING), oauthAudience != null ? oauthAudience : "");
        Preferences.setProperty(getQualifiedKey(OAUTH_REQUIRED_SCOPE_SETTING), oauthRequiredScope != null ? oauthRequiredScope : "");

        // Backward compatibility: still persist legacy settings.
        Preferences.setProperty(getQualifiedKey(OAUTH_CLIENT_ID_SETTING), oauthClientId != null ? oauthClientId : "");
        Preferences.setProperty(getQualifiedKey(OAUTH_BEARER_TOKEN_HASH_SETTING), oauthTokenHash != null ? oauthTokenHash : "");

        // Keep plaintext keys empty.
        Preferences.setProperty(getQualifiedKey(BASIC_PASSWORD_SETTING), "");
        Preferences.setProperty(getQualifiedKey(OAUTH_BEARER_TOKEN_SETTING), "");

        // Backward compatibility with legacy toggle.
        Preferences.setProperty(getQualifiedKey(BasicAuthConfig.AUTH_ENABLED_SETTING), String.valueOf(mode == AuthMode.BASIC));
    }
}
