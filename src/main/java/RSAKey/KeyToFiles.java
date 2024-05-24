package RSAKey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class KeyToFiles {
    private PrivateKey privateKey;PublicKey publicKey;

    public void savePemFile(String fileName, String header, byte[] keyBytes) throws IOException {
        Base64.Encoder encoder = Base64.getMimeEncoder(64, new byte[]{'\n'});
        String encodedKey = encoder.encodeToString(keyBytes);
        String pemKey = String.format("-----BEGIN %s-----\n%s\n-----END %s-----\n", header, encodedKey, header);
        Files.write(Paths.get(fileName), pemKey.getBytes());
    }
}
