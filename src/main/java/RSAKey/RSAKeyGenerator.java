package RSAKey;

import java.security.*;

public class RSAKeyGenerator {

    public KeyPair getKeyGenerator() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }


}
