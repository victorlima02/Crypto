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
package crypto.util;

import java.util.Arrays;
import java.util.BitSet;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Ignore;

/**
 *
 * @author Victor de Lima Soares
 */
public class BitBufferTest {

    public BitBufferTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of close method, of class BitBuffer.
     */
    @Test
    public void testClose() {
        System.out.println("close");
        BitBuffer instance = new BitBuffer();

        instance.set(1);
        instance.set(3, 7);
        System.out.println(instance);
        instance.close();
        try {
            System.out.println(instance);
        } catch (NullPointerException ex) {

        }
    }

    /**
     * Test of clone method, of class BitBuffer.
     */
    @Test
    public void testClone() {
        System.out.println("clone");
        BitBuffer instance = new BitBuffer();
        Object expResult = instance;
        Object result = instance.clone();
        assertEquals(expResult, result);
    }

    /**
     * Test of copy method, of class BitBuffer.
     */
    @Test
    public void testCopy_BitSet() {
        System.out.println("copy");
        byte bytes[] = {1, 2, 3};
        BitSet origin = BitSet.valueOf(bytes);
        BitBuffer instance = new BitBuffer();
        instance.copy(origin);
        Object expResult = new BitBuffer(origin);
        Object result = instance;
        assertEquals(expResult, result);
    }

    /**
     * Test of copy method, of class BitBuffer.
     */
    @Test
    public void testCopy_BitBuffer() {
        System.out.println("copy");
        BitBuffer origin = new BitBuffer("123".toCharArray());
        BitBuffer instance = new BitBuffer();
        instance.copy(origin);
        Object expResult = origin;
        Object result = instance;
        assertEquals(expResult, result);
    }

    /**
     * Test of overwrite method, of class BitBuffer.
     */
    @Test
    public void testOverwrite_int_BitBuffer() {
        System.out.println("overwrite");
        int pos = 3;
        BitBuffer origin = new BitBuffer("123".toCharArray());
        BitBuffer instance = new BitBuffer(10);
        instance.overwrite(pos, origin);

        System.out.println(origin);
        System.out.println(Arrays.toString(origin.toByteArray()));

        System.out.println(instance);
        System.out.println(Arrays.toString(instance.toByteArray()));

        BitBuffer expResult = origin;
        BitBuffer result = instance.get(3, instance.length());
        if (!expResult.equals(result)) {
            fail();
        }

    }

    /**
     * Test of overwrite method, of class BitBuffer.
     */
    @Test
    public void testOverwrite_int_BitSet() {
        System.out.println("overwrite");
        int pos = 0;
        byte bytes[] = {1, 2, 3};
        BitSet origin = BitSet.valueOf(bytes);

        BitBuffer instance = new BitBuffer();
        instance.overwrite(pos, origin);

        BitBuffer expResult = new BitBuffer(origin);
        BitBuffer result = instance;
        if (!expResult.equals(result)) {
            fail();
        }
    }

    /**
     * Test of overwrite method, of class BitBuffer.
     */
    @Test
    public void testOverwrite_3args() {
        System.out.println("overwrite");
        int pos = 3;
        BitBuffer origin = new BitBuffer("12356".toCharArray());
        int nBits = 3;
        BitBuffer instance = new BitBuffer();
        instance.overwrite(pos, origin, nBits);

        BitBuffer expResult = origin.get(0, nBits);
        BitBuffer result = instance.get(pos, pos + nBits);
        assertEquals(expResult, result);
    }

    /**
     * Test of overwrite method, of class BitBuffer.
     */
    @Test
    public void testOverwrite_4args_1() {
        System.out.println("overwrite");

        int pos = 5;
        BitBuffer origin = new BitBuffer("12356".toCharArray());
        int initialPos = 2;
        int nBits = 3;

        BitBuffer instance = new BitBuffer();

        instance.overwrite(pos, origin, initialPos, nBits);

        BitBuffer expResult = origin.get(initialPos, initialPos + nBits);
        BitBuffer result = instance.get(pos, pos + nBits);

        assertEquals(expResult, result);
    }

    /**
     * Test of and method, of class BitBuffer.
     */
    @Test
    public void testAnd_BitBuffer() {
        System.out.println("and");
        BitBuffer set = new BitBuffer("12356".toCharArray());;
        BitBuffer instance = new BitBuffer();
        instance.and(set);

        BitBuffer expResult = new BitBuffer();
        BitBuffer result = instance;

        assertEquals(expResult, result);
    }

    /**
     * Test of refresh method, of class BitBuffer.
     */
    @Test
    public void testRefresh_0args() {
        System.out.println("refresh");
        BitBuffer instance = new BitBuffer(12);
        instance.refresh();

        BitBuffer expResult = new BitBuffer(12);
        BitBuffer result = instance;
        assertEquals(expResult, result);
    }

    /**
     * Test of refresh method, of class BitBuffer.
     */
    @Test
    public void testRefresh_int() {
        System.out.println("refresh");
        int nbits = 12;
        BitBuffer instance = new BitBuffer();
        instance.refresh(nbits);

        BitBuffer expResult = new BitBuffer(12);
        BitBuffer result = instance;
        assertEquals(expResult, result);
    }

    /**
     * Test of replace method, of class BitBuffer.
     */
    @Test
    public void testReplace_BitBuffer() {
        System.out.println("replace");
        BitBuffer set = new BitBuffer("12356".toCharArray());
        BitBuffer instance = new BitBuffer();
        instance.replace(set);

        BitBuffer expResult = set;
        BitBuffer result = instance;
        assertEquals(expResult, result);
    }

    /**
     * Test of shiftCyclicalRight method, of class BitBuffer.
     */
    @Test
    public void testShiftCyclicalRight() {
        System.out.println("shiftCyclicalRight");
        BitBuffer instance = new BitBuffer("12356".toCharArray());
        int nBits = 2;
        int ringSize = 15;

        System.out.println(instance.get(0, ringSize));
        instance.shiftCyclicalRight(nBits, ringSize);
        System.out.println(instance.get(0, ringSize));
    }

    /**
     * Test of shiftCyclicalLeft method, of class BitBuffer.
     */
    @Test
    public void testShiftCyclicalLeft() {
        System.out.println("shiftCyclicalLeft");
        BitBuffer instance = new BitBuffer("12356".toCharArray());
        int nBits = 2;
        int ringSize = 15;

        System.out.println(instance.get(0, ringSize));
        instance.shiftCyclicalLeft(nBits, ringSize);
        System.out.println(instance.get(0, ringSize));
        
        nBits = 2;
        instance.shiftCyclicalLeft(nBits, ringSize);
        System.out.println(instance.get(0, ringSize));
        instance.shiftCyclicalRight(nBits, ringSize);
        System.out.println(instance.get(0, ringSize));
        
        nBits = 3;
        instance.shiftCyclicalLeft(nBits, ringSize);
        System.out.println(instance.get(0, ringSize));
        instance.shiftCyclicalRight(nBits, ringSize);
        System.out.println(instance.get(0, ringSize));
        
        nBits = 2;
        instance.shiftCyclicalRight(nBits, ringSize);
        System.out.println(instance.get(0, ringSize));
    }
}
