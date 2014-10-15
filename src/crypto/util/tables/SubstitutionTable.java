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
package crypto.util.tables;

import crypto.util.BitBuffer;
import java.util.BitSet;
import java.util.List;

/**
 * Substitution tables for <code>BitSets</code>
 *
 * @author Victor de Lima Soares
 * @version 1.0
 */
public class SubstitutionTable {

    private final List<List<BitSet>> elementsTable;

    public SubstitutionTable(List<List<BitSet>> elementsTable) {
        this.elementsTable = elementsTable;
    }

    public void replace(final BitBuffer bits, int x, int y) {
        bits.replace(getElement(x, y));
    }
    
    /**
     * Will return a clone from the element on the xth column and yth line.
     * @param x Column
     * @param y line
     * @return replacement element
     */
    public BitSet getElement(int x, int y){
        return (BitSet) elementsTable.get(y).get(x).clone();
    }
}
