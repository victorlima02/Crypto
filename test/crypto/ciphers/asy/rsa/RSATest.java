package crypto.ciphers.asy.rsa;

import java.math.BigInteger;
import javafx.util.Pair;
import org.junit.Test;
import static org.junit.Assert.*;

import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Ignore;

/**
 *
 * @author Victor de Lima Soares
 */
public class RSATest {

    public RSATest() {
    }

    private final RSA rsa = new RSA(512);

    /**
     * Test of encrypt method, of class RSA.
     */
    @Test
    public void testEncrypt_Pair_String() {
        System.out.println("encrypt");

        String plainText = "test";
        BigInteger cipherText = RSA.encrypt(rsa.getPublicKeyPair(), plainText);
        String decryptedText = RSA.BigIntegerToString(rsa.decrypt(cipherText));
        System.out.println(plainText);
        System.out.println(decryptedText);
        assertEquals("enc/dec", plainText, decryptedText);
    }


    /**
     * Test of encrypt method, of class RSA.
     */
    @Test
    public void testEncrypt_Pair_BigInteger() {
        System.out.println("encrypt");
        BigInteger msg = BigInteger.TEN;
        BigInteger expResult = BigInteger.TEN;
        BigInteger cipherMsg = RSA.encrypt(rsa.getPublicKeyPair(), msg);
        BigInteger decryptedMsg = rsa.decrypt(cipherMsg);
        System.out.println(msg);
        System.out.println(decryptedMsg);
        assertEquals("enc/dec",expResult, decryptedMsg);
    }

}
