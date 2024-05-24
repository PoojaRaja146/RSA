package RSA;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class RSADecrypt {

    private final PublicKey publicKey;
    private final byte[] encryptedMessageBytes;
    public RSADecrypt(PublicKey publicKey, byte[] encryptedMessageBytes) {

        this.publicKey = publicKey;
        this.encryptedMessageBytes = encryptedMessageBytes;
    }

    public String RSAEncryptDecrypt() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
        return new String(decryptedMessageBytes);
    }
}
