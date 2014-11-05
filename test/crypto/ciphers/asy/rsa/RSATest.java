package crypto.ciphers.asy.rsa;

import crypto.ciphers.block.feistel.des.DES;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
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

        String plainText = "testABCDEabcde";
        BigInteger cipherText = RSA.encrypt(rsa.getPublicKeyPair(), plainText);
        String decryptedText = RSA.BigIntegerToString(rsa.decrypt(cipherText));
        System.out.println(plainText);
        System.out.println(Arrays.toString(plainText.getBytes(Charset.forName("utf-8"))));
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
        assertEquals("enc/dec", expResult, decryptedMsg);
    }

    /**
     * Test of encrypt method, of class RSA.
     */
    @Test
    public void testEncrypt_Pair_bytes() throws NoSuchAlgorithmException {
        System.out.println("encrypt");
        byte[] newKey = DES.genkey(true);
        //byte[] newKey = {-10,-1,-90,0,0,5};
        byte[] expResult = newKey.clone();
        
        BigInteger cipherMsg = RSA.encrypt(rsa.getPublicKeyPair(), new BigInteger(newKey) );
        byte[] decryptedMsg = rsa.decrypt(cipherMsg).toByteArray();
        System.out.println(Arrays.toString(expResult));
        System.out.println(Arrays.toString(decryptedMsg));
        assertArrayEquals("enc/dec", expResult, decryptedMsg);

    }
}
