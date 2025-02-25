package io.heckel.ntfy.util;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.security.KeyStore;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class KeystoreHelper {

    private static final String KEY_ALIAS = "NtfySecureKey";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final int KEY_SIZE = 256;

    // Generate AES key in Keystore (only needs to be called once)
    public static void generateKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);

        // Only generate the key if it doesn't already exist.
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            KeyGenParameterSpec keySpec = new KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
            )
                    .setKeySize(KEY_SIZE)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build();

            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
            keyGenerator.init(keySpec);
            keyGenerator.generateKey(); // The key is stored inside the Keystore.
        }
    }

    // Retrieve the AES key from Keystore
    public static SecretKey getSecretKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);

        if (!keyStore.containsAlias(KEY_ALIAS)) {
            // Optionally, you can generate the key if it doesn't exist:
            generateKey();
        }

        KeyStore.Entry entry = keyStore.getEntry(KEY_ALIAS, null);
        if (entry == null || !(entry instanceof KeyStore.SecretKeyEntry)) {
            throw new Exception("No key found under alias: " + KEY_ALIAS);
        }
        return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
    }
}