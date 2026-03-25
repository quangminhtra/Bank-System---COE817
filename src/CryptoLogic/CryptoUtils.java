package CryptoLogic;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public final class CryptoUtils {
    // Secure random generator used for keys, IVs, nonces, and random values
    private static final SecureRandom RANDOM = new SecureRandom();

    private CryptoUtils() {}

    public static KeyPair generateRSAKeyPair() throws Exception {
        // Generate RSA key pair for the server
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    public static byte[] rsaEncrypt(PublicKey publicKey, byte[] plain) throws Exception {
        // RSA encryption protects registration data in transit
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plain);
    }

    public static byte[] rsaDecrypt(PrivateKey privateKey, byte[] cipherBytes) throws Exception {
        // RSA decryption recovers the original registration payload
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(cipherBytes);
    }

    public static byte[] aesGcmEncrypt(SecretKey key, byte[] plain) throws Exception {
        // AES-GCM is used during authentication for confidentiality and integrity together
        byte[] iv = randomBytes(12);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] ct = cipher.doFinal(plain);

        // Store IV in front of ciphertext so the receiver can decrypt later
        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return out;
    }

    public static byte[] aesGcmDecrypt(SecretKey key, byte[] ivPlusCipher) throws Exception {
        // Split received bytes into IV and ciphertext+tag
        byte[] iv = Arrays.copyOfRange(ivPlusCipher, 0, 12);
        byte[] ct = Arrays.copyOfRange(ivPlusCipher, 12, ivPlusCipher.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(ct);
    }

    public static byte[] aesCbcEncrypt(SecretKey key, byte[] plain) throws Exception {
        // AES-CBC protects secure transaction messages after login
        byte[] iv = randomBytes(16);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new javax.crypto.spec.IvParameterSpec(iv));
        byte[] ct = cipher.doFinal(plain);

        // Prefix Iv to ciphertext so decryption can rebuild the cipher state
        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return out;
    }

    public static byte[] aesCbcDecrypt(SecretKey key, byte[] ivPlusCipher) throws Exception {
        // Read IV first, then decrypt the remaining ciphertex
        byte[] iv = Arrays.copyOfRange(ivPlusCipher, 0, 16);
        byte[] ct = Arrays.copyOfRange(ivPlusCipher, 16, ivPlusCipher.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new javax.crypto.spec.IvParameterSpec(iv));
        return cipher.doFinal(ct);
    }

    public static SecretKey generateAESKey(int bits) throws Exception {
        // Generate a fresh AES key of the requested length.
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(bits);
        return kg.generateKey();
    }

    public static byte[] hmacSha256(SecretKey key, byte[] data) throws Exception {
        // HMAC-SHA256 provides message integrity and authenticity.
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key.getEncoded(), "HmacSHA256"));
        return mac.doFinal(data);
    }

    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        // Constant-time comparision 
        return MessageDigest.isEqual(a, b);
    }

    public static byte[] randomBytes(int len) {
        // Create securely random bytes for IVs, salts, nonces, and randomness
        byte[] out = new byte[len];
        RANDOM.nextBytes(out);
        return out;
    }

    public static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int keyLenBytes) throws Exception {
        // Derive a key from password, salt, and iteration count.
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, iterations, keyLenBytes * 8);
        return factory.generateSecret(spec).getEncoded();
    }

    public static SecretKey hkdfExpand(byte[] ikm, String label, int len) throws Exception {
        // Expand master seed into a new key 
        byte[] prk = hmacSha256(new SecretKeySpec(new byte[32], "HmacSHA256"), ikm);
        byte[] okm = new byte[len];
        byte[] previous = new byte[0];
        int copied = 0;
        int counter = 1;

        while (copied < len) {
            byte[] input = new byte[previous.length + label.getBytes(StandardCharsets.UTF_8).length + 1];
            System.arraycopy(previous, 0, input, 0, previous.length);

            byte[] labelBytes = label.getBytes(StandardCharsets.UTF_8);
            System.arraycopy(labelBytes, 0, input, previous.length, labelBytes.length);
            input[input.length - 1] = (byte) counter;

            previous = hmacSha256(new SecretKeySpec(prk, "HmacSHA256"), input);

            int chunk = Math.min(previous.length, len - copied);
            System.arraycopy(previous, 0, okm, copied, chunk);
            copied += chunk;
            counter++;
        }

        return new SecretKeySpec(okm, "AES");
    }

    public static String b64(byte[] data) {
        // Encode raw bytes into Base64 text for sending over sockets
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] unb64(String value) {
        // Decode Base64 text back into raw byte
        return Base64.getDecoder().decode(value);
    }

    public static String utf8(byte[] data) {
        // Convert byte array to UTF-8 string
        return new String(data, StandardCharsets.UTF_8);
    }

    public static byte[] bytes(String text) {
        // Convert string into UTF-8 bytes
        return text.getBytes(StandardCharsets.UTF_8);
    }

    public static SecretKey aesKeyFromBytes(byte[] data) {
        // Wrap raw bytes as an AES key Oject
        return new SecretKeySpec(data, "AES");
    }

    public static SecretKey hmacKeyFromBytes(byte[] data) {
        // Wrap raw bytes as an HMAC-SHA256 
        return new SecretKeySpec(data, "HmacSHA256");
    }

    public static String encodePublicKey(PublicKey key) {
        // Convert public key into Base64 string for transmission
        return b64(key.getEncoded());
    }

    public static PublicKey decodePublicKey(String b64) throws Exception {
        // Rebuild RSA public key from Base64-encoded bytes
        X509EncodedKeySpec spec = new X509EncodedKeySpec(unb64(b64));
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }
}