package RSAKey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ExtractKeysFromFile {
    public static Object getKey(String filename, String keyType) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeySpecException, IOException {
        String key = new String(Files.readAllBytes(Paths.get(filename)));
        String keyPEM = key.replace("-----BEGIN " + keyType.toUpperCase() + " KEY-----", "")
                .replace("-----END " + keyType.toUpperCase() + " KEY-----", "")
                .replaceAll("\\s", "");

        byte[] encoded = Base64.getDecoder().decode(keyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        if ("public".equalsIgnoreCase(keyType)) {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
            return keyFactory.generatePublic(keySpec);
        } else if ("private".equalsIgnoreCase(keyType)) {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            return keyFactory.generatePrivate(keySpec);
        } else {
            throw new IllegalArgumentException("Invalid key type: " + keyType);
        }
    }
}
