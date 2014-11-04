/*
 * This code was written for an assignment for concept demonstration purposes:
 *  caution required
 *
 * The MIT License
 *
 * Copyright 2014 Victor de Lima Soares.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package crypto.ciphers.asy.rsa;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import javafx.util.Pair;

/**
 * Class to perform RSA computations.
 *
 * @author Victor de Lima Soares
 * @version 1.0
 */
public class RSA {

    /**
     * Private key component: d.
     * <p>
     * d=e^-1 mod phi
     * </p>
     *
     * @since 1.0
     */
    private BigInteger d;

    /**
     * Public key component: e.
     *
     * @since 1.0
     */
    private final BigInteger e;

    /**
     * Modulus argument to be used with the public key.
     *
     * <p>
     * n=(p)*(q)
     * </p>
     *
     * @since 1.0
     */
    private final BigInteger n;

    /**
     * Modulus argument to be used for encryption and decryption.
     *
     * <p>
     * phi=(p-1)*(q-1)
     * </p>
     *
     * @since 1.0
     */
    private final BigInteger phi;

    /**
     * Default Charset to be used for encoding strings.
     *
     * @since 1.0
     */
    public static final Charset CHARSET = Charset.forName("utf-8");

    /**
     * Create a new RSA object with random primes (probably primes).
     *
     * <p>
     * This method will generate all parameters to execute the RSA algorithm,
     * including the computation for the private and public keys.
     * </p>
     *
     * @since 1.0
     * @param numBits Number of bits for p and q.
     * @see SecureRandom
     */
    public RSA(int numBits) {
        SecureRandom generator = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(numBits, generator);
        BigInteger q = BigInteger.probablePrime(numBits, generator);

        n = p.multiply(q);
        phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        //Calculate e
        BigInteger tmp;
        do {

            tmp = new BigInteger(numBits * 2, generator);

        } while ((tmp.compareTo(phi) > 0) || !(tmp.gcd(phi).equals(BigInteger.ONE)));

        e = tmp;
        d = e.modInverse(phi);

    }

    /**
     * Encrypts a message for someone else, using their public key.
     *
     * @param publicKeyPair Pair (n,e)
     * @param msg
     * @return encrypted message
     */
    public static BigInteger encrypt(Pair<BigInteger, BigInteger> publicKeyPair, String msg) {
        return encrypt(publicKeyPair, StringToBigInteger(msg));
    }

    /**
     * Encrypts a message for someone else, using their public key.
     *
     * <p>
     * This function will not correctly work if the first byte if non-positive.
     * Protocols using this function should be aware of this and implement a
     * protocol dependent correction; e.i, invert the first byte on the input
     * and after on the decrypted message with some signaling - padding can also
     * be used.
     * </p>
     *
     * @since 1.0
     * @param publicKeyPair Pair (n,e)
     * @param msg
     * @return encrypted message
     */
    public static BigInteger encrypt(Pair<BigInteger, BigInteger> publicKeyPair, byte[] msg) {
        return encrypt(publicKeyPair, new BigInteger(msg));
    }

    /**
     * Encrypts a message for someone else, using their public key.
     *
     * @param publicKeyPair Pair (n,e)
     * @param msg
     * @return encrypted message
     */
    public static BigInteger encrypt(Pair<BigInteger, BigInteger> publicKeyPair, BigInteger msg) {
        BigInteger n = publicKeyPair.getKey();
        BigInteger e = publicKeyPair.getValue();
        return msg.modPow(e, n);
    }

    /**
     * Decrypts a message encrypted with this instance public key.
     *
     * @since 1.0
     * @param msg Message to be decrypted.
     * @return Decrypted message.
     */
    public BigInteger decrypt(BigInteger msg) {
        return msg.modPow(d, n);
    }

    /**
     * Converts a String into a BigInteger (utf-8 encoding).
     *
     * @since 1.0
     * @param msg String to be converted.
     * @return BigInteger representation.
     */
    public static BigInteger StringToBigInteger(String msg) {
        return new BigInteger(msg.getBytes(CHARSET));
    }

    /**
     * Converts a BigInteger into a string (utf-8 encoding).
     *
     * @since 1.0
     * @param msg BigInteger to be converted.
     * @return Decoded string.
     */
    public static String BigIntegerToString(BigInteger msg) {
        return new String(msg.toByteArray(), CHARSET);
    }

    /**
     * Converts a BigInteger into a byte array.
     *
     * @since 1.0
     * @param msg BigInteger to be converted.
     * @return Byte array.
     */
    public static byte[] bigIntegerToByteArray(BigInteger msg) {
        return msg.toByteArray();
    }

    /**
     * Returns the public key (e) component of RSA.
     *
     * @since 1.0
     * @return e
     */
    public BigInteger getE() {
        return e;
    }

    /**
     * Return the n component.
     *
     * <p>
     * Modulus argument to be used with the public key.
     * </p>
     * <p>
     * n=(p)*(q)
     * </p>
     *
     * @since 1.0
     * @return n
     */
    public BigInteger getN() {
        return n;
    }

    /**
     * Return the (n,public key) or (n,e) public key pair.
     *
     * @since 1.0
     * @return (n,e)
     */
    public Pair<BigInteger, BigInteger> getPublicKeyPair() {
        return new Pair<>(n, e);
    }
}
