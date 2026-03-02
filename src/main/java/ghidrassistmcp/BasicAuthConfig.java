package ghidrassistmcp;

import ghidra.framework.preferences.Preferences;

/**
 * Centralized auth configuration helpers including plaintext-to-hash migration.
 */
public final class BasicAuthConfig {

    private static final String SETTINGS_CATEGORY = "GhidrAssistMCP";
    public static final String AUTH_ENABLED_SETTING = "Basic Auth Enabled";
    public static final String AUTH_USERNAME_SETTING = "Basic Auth Username";
    public static final String AUTH_PASSWORD_SETTING = "Basic Auth Password";
    public static final String AUTH_PASSWORD_HASH_SETTING = "Basic Auth Password Hash";

    public static final String DEFAULT_AUTH_USERNAME = "mcp";

    private BasicAuthConfig() {
    }

    public static String getQualifiedKey(String setting) {
        return SETTINGS_CATEGORY + "." + setting;
    }

    public static String resolvePasswordHash() {
        String hash = Preferences.getProperty(getQualifiedKey(AUTH_PASSWORD_HASH_SETTING), "");
        if (PasswordVerifier.isHashedPassword(hash)) {
            return hash;
        }
        return "";
    }

    public static String chooseHashForSave(String enteredPassword, String existingHash) {
        if (enteredPassword != null && !enteredPassword.isEmpty()) {
            return PasswordVerifier.hashPassword(enteredPassword);
        }
        return existingHash != null ? existingHash : "";
    }

    public static void persistAuthSettings(boolean enabled, String username, String passwordHash) {
        Preferences.setProperty(getQualifiedKey(AUTH_ENABLED_SETTING), String.valueOf(enabled));
        Preferences.setProperty(getQualifiedKey(AUTH_USERNAME_SETTING), username != null ? username : "");
        Preferences.setProperty(getQualifiedKey(AUTH_PASSWORD_HASH_SETTING), passwordHash != null ? passwordHash : "");
        // Keep plaintext key empty after migration.
        Preferences.setProperty(getQualifiedKey(AUTH_PASSWORD_SETTING), "");
    }
}
