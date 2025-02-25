package io.heckel.ntfy.util;

import android.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;

public class DecryptionHelper {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    // IV size (in bytes) must match the one used during encryption (usually 12 bytes for GCM)
    private static final int IV_SIZE = 12;
    private static final int TAG_LENGTH = 128;

    public static String decrypt(String encryptedText) throws Exception {
        try {
            SecretKey key = KeystoreHelper.getSecretKey();
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);

            // Decode the Base64 encoded string.
            byte[] decodedBytes = Base64.decode(encryptedText, Base64.DEFAULT);

            // Extract the IV from the beginning of the byte array.
            byte[] iv = new byte[IV_SIZE];
            System.arraycopy(decodedBytes, 0, iv, 0, IV_SIZE);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);

            // Initialize the cipher for decryption using the extracted IV.
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

            // Decrypt the ciphertext (bytes after the IV).
            byte[] decryptedBytes = cipher.doFinal(decodedBytes, IV_SIZE, decodedBytes.length - IV_SIZE);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
        }
        // Return the original encrypted text if decryption fails (you may wish to handle this differently)
        return encryptedText;
    }
}
