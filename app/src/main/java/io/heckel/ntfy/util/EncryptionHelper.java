package io.heckel.ntfy.util;

import android.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

public class EncryptionHelper {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    // TAG_LENGTH in bits (typically 128 bits for AES-GCM)
    private static final int TAG_LENGTH = 128;

    public static String encrypt(String plainText) throws Exception {
        try {
            SecretKey key = KeystoreHelper.getSecretKey();
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);

            // Let the Android Keystore generate a secure IV automatically.
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] iv = cipher.getIV(); // Automatically generated IV (typically 12 bytes)

            // Encrypt the plaintext.
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            // Combine the IV and ciphertext.
            byte[] combined = new byte[iv.length + encryptedBytes.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);

            // Encode the result in Base64.
            return Base64.encodeToString(combined, Base64.DEFAULT);
        } catch (Exception e) {
            e.printStackTrace();
        }
        // Return the plain text if encryption fails (you may wish to handle this differently)
        return plainText;
    }
}
