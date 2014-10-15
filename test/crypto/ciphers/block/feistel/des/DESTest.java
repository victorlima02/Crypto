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
package crypto.ciphers.block.feistel.des;

import crypto.util.BitBuffer;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import static org.junit.Assert.*;
import org.junit.Ignore;
import org.junit.Test;

/**
 *
 * @author Victor de Lima Soares
 */
public class DESTest {

    public DESTest() {
    }

    /**
     * Test of getRoundKey method, of class DES.
     */
    @Ignore
    @Test
    public void testGetRoundKey() throws NoSuchAlgorithmException, UnsupportedEncodingException {
        System.out.println("getRoundKey");

        DES instance = new DES();

        BitBuffer key = new BitBuffer(DES.genkey("password".getBytes("utf-8")));
        BitBuffer keyBuffer = (BitBuffer) key.clone();
        
        for (int round = 0; round < instance.getNRounds(); round++) {
            System.out.println(instance.getRoundKey(keyBuffer, round));
        }

        System.out.println();

        keyBuffer = (BitBuffer) key.clone();
        for (int round = 0; round < instance.getNRounds(); round++) {
            System.out.println(instance.getRoundKeyDescryption(keyBuffer, round));
        }

    }

   

    /**
     * Test of fFunction method, of class DES.
     */
    @Ignore
    @Test
    public void testFFunction() {
        System.out.println("fFunction");
        BitBuffer right = null;
        BitBuffer roundKey = null;
        DES instance = new DES();
        BitBuffer expResult = null;
        BitBuffer result = instance.fFunction(right, roundKey);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of finalPermutation method, of class DES.
     */
    @Test
    public void testFinalPermutation() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        System.out.println("finalPermutation");
        
        BitBuffer cipherText = new BitBuffer("12345678".getBytes());
        BitBuffer expected = new BitBuffer("12345678".getBytes());
        BitBuffer expectedClone = new BitBuffer("12345678".getBytes());
        DES instance = new DES();

        System.out.println(cipherText);
        instance.initialPermutation(cipherText);
        
        System.out.println(cipherText);
        instance.finalPermutation(cipherText);
        System.out.println(cipherText);
        
        System.out.println();
        expectedClone.xor(cipherText);
        System.out.println(expectedClone);
        assertEquals(expected, cipherText);
    }

    /**
     * Test of initialPermutation method, of class DES.
     */
    @Ignore
    @Test
    public void testInitialPermutation() {
        System.out.println("initialPermutation");
        BitBuffer cipherText = null;
        DES instance = new DES();
        instance.initialPermutation(cipherText);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
}
