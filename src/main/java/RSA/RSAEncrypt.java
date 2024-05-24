package RSA;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Base64;

public class RSAEncrypt {
    String message;
    PrivateKey privateKey;
    public RSAEncrypt(PrivateKey privateKey, String message) {
        this.message = message;
        this.privateKey = privateKey;
    }
    public byte[] getRsaEncryptedMessage() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] secretMessageBytes = message.getBytes();
        return encryptCipher.doFinal(secretMessageBytes);

    }


}
