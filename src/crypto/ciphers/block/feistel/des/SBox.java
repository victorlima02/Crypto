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
import crypto.util.tables.SubstitutionTable;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collections;
import java.util.List;

/**
 * DES S-BOX
 *
 * @author Victor de Lima Soares
 * @version 1.0
 */
public class SBox extends SubstitutionTable {

    public final static int INPUT_SIZE = 6;
    public final static int OUTPUT_SIZE = 4;

    public SBox(List<List<BitSet>> elementsTable) {
        super(elementsTable);
    }

    /**
     * Calculates the position for the bits replacement in a s-box, y axe.
     *
     * @since 1.0
     * @param bits Bits to be replaced.
     * @return y replacement position.
     */
    private byte getY(BitBuffer bits) {
        BitBuffer yBin = new BitBuffer(2);
        yBin.set(0, bits.get(0));
        yBin.set(1, bits.get(5));        
        return (yBin.toByteArray().length>0)?yBin.toByteArray()[0]:0;
    }

    /**
     * Calculates the position for the bits replacement in a s-box, x-axe (lines).
     *
     * @since 1.0
     * @param bits Bits to be replaced. 
     * @return x replacement position.
     */
    private byte getX(BitBuffer bits) {
        BitBuffer xBin = new BitBuffer(4);
        xBin.set(0, bits.get(1));
        xBin.set(1, bits.get(2)); 
        xBin.set(2, bits.get(3));
        xBin.set(3, bits.get(4)); 
        return (xBin.toByteArray().length>0)?xBin.toByteArray()[0]:0;
    }

    /**
     * Replace the bits by the bits found in the replacement table.
     *
     * @since 1.0
     * @param bits Bits to be replaced.
     */
    public void replace(BitBuffer bits) {
        super.replace(bits, getX(bits), getY(bits));
    }

    /**
     * Transforms a byte matrix into a BitSet matrix (unmodifiable).
     *
     * @since 1.0
     * @param args Byte matrix.
     * @return <code>BitSet</code> matrix
     */
    public static List<List<BitSet>> byteToBitSetMatrix(byte[][] args) {

        List<List<BitSet>> elementsTable = new ArrayList<>(args.length);

        for (byte[] arg : args) {

            List<BitSet> bitSetList = new ArrayList<>(arg.length);

            for (int j = 0; j < arg.length; j++) {
                bitSetList.add(BitSet.valueOf(new byte[]{arg[j]}));
            }

            elementsTable.add(Collections.unmodifiableList(bitSetList));
        }

        elementsTable = Collections.unmodifiableList(elementsTable);
        return elementsTable;
    }
}
