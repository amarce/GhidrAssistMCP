package ghidrassistmcp;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Utility for hashing and verifying passwords using PBKDF2.
 */
public final class PasswordVerifier {

    private static final String HASH_PREFIX = "pbkdf2";
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 120000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_BYTES = 32;

    private PasswordVerifier() {
    }

    public static boolean isHashedPassword(String value) {
        return value != null && value.startsWith(HASH_PREFIX + "$");
    }

    public static String hashPassword(String password) {
        if (password == null) {
            password = "";
        }

        byte[] salt = new byte[SALT_BYTES];
        new SecureRandom().nextBytes(salt);

        byte[] hash = deriveKey(password.toCharArray(), salt, ITERATIONS, KEY_BYTES);
        String saltBase64 = Base64.getEncoder().encodeToString(salt);
        String hashBase64 = Base64.getEncoder().encodeToString(hash);
        return HASH_PREFIX + "$" + ITERATIONS + "$" + saltBase64 + "$" + hashBase64;
    }

    public static boolean verifyPassword(String candidatePassword, String storedHash) {
        if (candidatePassword == null || storedHash == null || storedHash.isEmpty()) {
            return false;
        }

        if (!isHashedPassword(storedHash)) {
            return constantTimeEquals(candidatePassword.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                storedHash.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }

        String[] parts = storedHash.split("\\$");
        if (parts.length != 4) {
            return false;
        }

        try {
            int iterations = Integer.parseInt(parts[1]);
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expectedHash = Base64.getDecoder().decode(parts[3]);
            byte[] actualHash = deriveKey(candidatePassword.toCharArray(), salt, iterations, expectedHash.length);
            return constantTimeEquals(actualHash, expectedHash);
        } catch (IllegalArgumentException | NumberFormatException e) {
            return false;
        }
    }

    public static boolean constantTimeEquals(byte[] left, byte[] right) {
        if (left == null || right == null) {
            return false;
        }
        return MessageDigest.isEqual(left, right);
    }

    private static byte[] deriveKey(char[] password, byte[] salt, int iterations, int keyBytes) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBytes * 8);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Failed to derive password hash", e);
        } finally {
            spec.clearPassword();
        }
    }
}
