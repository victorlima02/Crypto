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

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.BitSet;
import java.util.stream.IntStream;

/**
 * Wraps <code>BitSet</code> to be auto closeable, cleaning itself after use.
 *
 * <p>
 * This class will lose in performance when compered with a <code>BitSet</code>
 * when closing several <code>BitBuffers</code> during client operation.
 * Practically not affecting other situations.
 * </p>
 *
 * @author Victor de Lima Soares
 * @version 1.0
 */
public class BitBuffer implements AutoCloseable, Cloneable, Serializable {

    private boolean closed = false;
    private BitSet data;
    private static final long serialVersionUID = 1L;

    /**
     * Creates a <code>BitBuffer</code>
     *
     * @since 1.0
     * @see BitSet#BitSet()
     */
    public BitBuffer() {
        data = new BitSet();
    }

    /**
     * Creates a <code>BitBuffer</code> whose initial size is large enough to
     * explicitly represent bits with indices in the range 0 through nbits-1.
     *
     * @since 1.0
     * @param nbits
     * @see BitSet#BitSet(int)
     */
    public BitBuffer(int nbits) {
        data = new BitSet(nbits);
    }

    /**
     * Creates a <code>BitBuffer</code> by wrapping the <code>BitSet</code>.
     *
     * @since 1.0
     * @param origin
     */
    public BitBuffer(BitSet origin) {
        data = origin;
    }

    /**
     * Create a new <code>BitBuffer</code> from byte[].
     *
     * @since 1.0
     * @param bytes
     */
    public BitBuffer(byte[] bytes) {
        this(BitSet.valueOf(ByteBuffer.wrap(bytes)));
    }

    /**
     * Create a new <code>BitBuffer</code> from char[] (utf-8).
     *
     * @since 1.0
     * @param chars
     */
    public BitBuffer(char[] chars) {
        this(toBitSet(chars));
    }

    /**
     * Access the delegated object for data operations.
     *
     * @since 1.0
     * @return
     */
    private BitSet getBitSet() {
        return data;
    }

    /**
     * Set a new BitSet as the data container.
     *
     * @since 1.0
     * @param origin
     */
    private void setBitSet(BitSet origin) {
        if (data != null) {
            data.clear();
        }
        data = origin;
    }

    /**
     * Clean the memory space used as buffer.
     *
     * @since 1.0
     */
    @Override
    public void close() {
        clear();
        setClosed(true);
        data = null;
    }

    /**
     * Before garbage collection this object needs to be cleaned.
     *
     * @since 1.0
     * @throws Throwable
     */
    @Override
    protected void finalize() throws Throwable {
        if (!isClosed()) {
            close();
        }
        super.finalize();
    }

    /**
     * Verify if the object was closed.
     *
     * @since
     * @return
     * <ul>
     * <li>true: if the method close was called on this.</li>
     * <li>false: otherwise.</li>
     * </ul>
     */
    private boolean isClosed() {
        return closed;
    }

    /**
     * Mark this object as closed or not.
     *
     * @since 1.0
     * @param closed
     */
    private void setClosed(boolean closed) {
        this.closed = closed;
    }

    /**
     * Creates a new <code>BitBuffer</code> with the same set bits as this.
     *
     * @since 1.0
     * @return Clone
     */
    @Override
    public Object clone() {
        BitBuffer newBuffer = new BitBuffer((BitSet) getBitSet().clone());
        return newBuffer;
    }

    /**
     * Copies the argument's bits into this object.
     *
     * <p>
     * This method does not overwrite bits, it will clear all bits and make an
     * or operation for coping the set bits.
     * </p>
     *
     * @since 1.0
     * @param origin
     */
    public void copy(BitSet origin) {
        clear();
        or(origin);
    }

    /**
     * Copies the argument's bits into this object.
     *
     * <p>
     * This method does not overwrite bits, it will clear all bits and make an
     * or operation for coping the set bits.
     * </p>
     *
     * @since 1.0
     * @param origin Bits to be copied.
     */
    public void copy(BitBuffer origin) {
        copy(origin.getBitSet());
    }

    /**
     * Copies,overwriting, the argument's bits into this object.
     *
     * <p>
     * It will stop at <code>origin.length()</code>.
     * </p>
     *
     * @since 1.0
     * @param pos position to start concatenation/overwriting.
     * @param origin Bits to be copied into this object.
     */
    public void overwrite(int pos, BitBuffer origin) {
        overwrite(pos, origin, 0, origin.length());
    }

    /**
     * Copies,overwriting, the argument's bits into this object.
     *
     * <p>
     * It will stop at <code>origin.length()</code>.
     * </p>
     *
     * @since 1.0
     * @param pos position to start concatenation/overwriting.
     * @param origin Bits to be copied into this object.
     */
    public void overwrite(int pos, BitSet origin) {
        overwrite(pos, origin, 0, origin.length());
    }

    /**
     * Copies,overwriting, the argument's bits into this object.
     *
     * @since 1.0
     * @param pos Position on this to start overwriting.
     * @param nBits Number of bits to copy.
     * @param origin Bits' origin to copy.
     */
    public void overwrite(int pos, BitBuffer origin, int nBits) {
        overwrite(pos, origin, 0, nBits);
    }

    /**
     * Copies the argument's bits into this object.
     *
     * @since 1.0
     * @param pos Position on this to start overwriting.
     * @param origin Bits' origin to copy.
     * @param initialPos Position to start copying, on the origin.
     * @param nBits Number of bits to copy.
     */
    public void overwrite(int pos, BitBuffer origin, int initialPos, int nBits) {
        overwrite(pos, origin.getBitSet(), initialPos, nBits);
    }

    /**
     * Copies the argument's bits into this object.
     *
     * @since 1.0
     * @param pos Position on this to start overwriting.
     * @param origin Bits' origin to copy.
     * @param initialPos Position to start copying, on the origin.
     * @param nBits Number of bits to copy.
     */
    public void overwrite(int pos, BitSet origin, int initialPos, int nBits) {
        for (int o = initialPos, i = pos; o < initialPos + nBits; o++, i++) {
            set(i, origin.get(o));
        }
    }

    public void and(BitBuffer set) {
        getBitSet().and(set.getBitSet());
    }

    public void and(BitSet set) {
        getBitSet().and(set);
    }

    public void andNot(BitBuffer set) {
        getBitSet().andNot(set.getBitSet());
    }

    public void andNot(BitSet set) {
        getBitSet().andNot(set);
    }

    public int cardinality() {
        return getBitSet().cardinality();
    }

    public void clear() {
        getBitSet().clear();
    }

    public void clear(int bitIndex) {
        getBitSet().clear(bitIndex);
    }

    public void clear(int fromIndex, int toIndex) {
        getBitSet().clear(fromIndex, toIndex);
    }

    @Override
    public boolean equals(Object obj) {

        if (!(obj instanceof BitBuffer)) {
            return false;
        }
        if (this == obj) {
            return true;
        }

        BitSet set = ((BitBuffer) obj).getBitSet();

        return getBitSet().equals(set);
    }

    public void flip(int bitIndex) {
        getBitSet().flip(bitIndex);
    }

    public void flip(int fromIndex, int toIndex) {
        getBitSet().flip(fromIndex, toIndex);
    }

    public boolean get(int bitIndex) {
        return getBitSet().get(bitIndex);
    }

    public BitBuffer get(int fromIndex, int toIndex) {
        return new BitBuffer(getBitSet().get(fromIndex, toIndex));
    }

    @Override
    public int hashCode() {
        return getBitSet().hashCode();
    }

    public boolean intersects(BitSet set) {
        return getBitSet().intersects(set);
    }

    /**
     * Verify if the bit buffer is empty or closed.
     *
     * @since 1.0
     * @return <ul>
     * <li>true: if it's closed or empty;</li>
     * <li>false: otherwise.</li>
     * </ul>
     */
    public boolean isEmpty() {
        if (isClosed()) {
            return true;
        }
        return getBitSet().isEmpty();
    }

    public int length() {
        return getBitSet().length();
    }

    public int nextClearBit(int fromIndex) {
        return getBitSet().nextClearBit(fromIndex);
    }

    public int nextSetBit(int fromIndex) {
        return getBitSet().nextSetBit(fromIndex);
    }

    public void or(BitBuffer set) {
        getBitSet().or(set.getBitSet());
    }

    public void or(BitSet set) {
        getBitSet().or(set);
    }

    public int previousClearBit(int fromIndex) {
        return getBitSet().previousClearBit(fromIndex);
    }

    public int previousSetBit(int fromIndex) {
        return getBitSet().previousSetBit(fromIndex);
    }

    public void set(int bitIndex) {
        getBitSet().set(bitIndex);
    }

    public void set(int bitIndex, boolean value) {
        getBitSet().set(bitIndex, value);
    }

    public void set(int fromIndex, int toIndex) {
        getBitSet().set(fromIndex, toIndex);
    }

    public void set(int fromIndex, int toIndex, boolean value) {
        getBitSet().set(fromIndex, toIndex, value);
    }

    public int size() {
        return getBitSet().size();
    }

    public IntStream stream() {
        return getBitSet().stream();
    }

    public byte[] toByteArray() {
        return getBitSet().toByteArray();
    }

    /**
     * Return a byte[] representation for the bits, with size n.
     * 
     * @since 1.0
     * @param n The size desired for the byte[] representation.
     * @return The byte[] representation.
     */
    public byte[] toByteArray(int n) {
        byte data[] = new byte[n];
        byte ori[] = getBitSet().toByteArray();
        System.arraycopy(ori, 0, data, 0, ori.length);
        clearKeyBuffer(ori);
        return data;
    }

    public long[] toLongArray() {
        return getBitSet().toLongArray();
    }

    @Override
    public String toString() {
        return getBitSet().toString();
    }

    public void xor(BitBuffer set) {
        getBitSet().xor(set.getBitSet());
    }

    public void xor(BitSet set) {
        getBitSet().xor(set);
    }

    /**
     * Clean all bits and replace the bit container with a new one.
     *
     * <p>
     * This will bring the object back to the creation state.
     * </p>
     *
     * @since 1.0
     * @see BitSet#BitSet()
     */
    public void refresh() {
        setBitSet(new BitSet());
    }

    /**
     * Clean all bits and replace the bit container with a new one.
     *
     * <p>
     * This will bring the object back to the creation state.
     * </p>
     *
     * @since 1.0
     * @param nbits
     * @see BitSet#BitSet(int)
     */
    public void refresh(int nbits) {
        setBitSet(new BitSet(nbits));
    }

    /**
     * Replace all bits for the bits in the argument.
     *
     * <p>
     * The new internal set will be a clone from the argument's bits.
     * </p>
     *
     * @since 1.0
     * @param set
     */
    public void replace(BitBuffer set) {
        setBitSet((BitSet) set.getBitSet().clone());
    }

    /**
     * Replace all bits for the bits in the argument.
     *
     * <p>
     * The new internal set will be the argument. It will be an wrap operation.
     * </p>
     *
     * @since 1.0
     * @param set
     */
    public void replace(BitSet set) {
        setBitSet(set);
    }

    /**
     * Right shift, cyclically.
     *
     * @since 1.0
     * @param nBits Number of bits to be shifted.
     * @param ringSize The buffer have not control of its size, so defining a
     * size for this operation will assure the right result.
     */
    public void shiftCyclicalRight(int nBits, int ringSize) {
        try (BitBuffer left = get(0, ringSize - nBits); BitBuffer right = get(ringSize - nBits, ringSize)) {

            overwrite(0, right, nBits);
            overwrite(nBits, left, ringSize - nBits);
        }
    }

    /**
     * Left shift, cyclically.
     *
     * @since 1.0
     * @param nBits Number of bits to be shifted.
     * @param ringSize The buffer have not control of its size, so defining a
     * size for this operation will assure the right result.
     */
    public void shiftCyclicalLeft(int nBits, int ringSize) {
        try (BitBuffer left = get(0, nBits); BitBuffer right = get(nBits, ringSize)) {

            overwrite(0, right, ringSize - nBits);
            overwrite(ringSize - nBits, left, nBits);
        }
    }

    /**
     * Create a new <code>BitBuffer</code> from byte[].
     *
     * @since 1.0
     * @param bytes
     * @return New <code>BitBuffer</code>
     */
    public static BitBuffer valueOf(byte[] bytes) {
        BitSet tmp = BitSet.valueOf(ByteBuffer.wrap(bytes));

        BitBuffer newBuffer = new BitBuffer(tmp);

        return newBuffer;
    }

    /**
     * Reads a char[] key and converts into a BitBuffer.
     *
     * <p>
     * All used buffers are cleaned before returning, except for the original
     * key, this class will not clean the argument, but it provides other
     * methods to clean it if desired.
     * </p>
     *
     * @since 1.0
     * @param chars key to be converted.
     * @return Bit set representing the key.
     */
    public static BitBuffer valueOf(final char[] chars) {

        BitBuffer newSet = new BitBuffer(toBitSet(chars));
        return newSet;
    }

    /**
     * Converts a char[] into a BitSet (utf-8).
     *
     * @since 1.0
     * @param chars
     * @return new bit set
     */
    public static BitSet toBitSet(final char[] chars) {

        CharBuffer charBuffer = CharBuffer.wrap(chars);
        ByteBuffer byteBuffer = Charset.forName("UTF-8").encode(charBuffer);

        BitSet newSet = BitSet.valueOf(byteBuffer);

        clearKeyBuffer(charBuffer.array()); // clear sensitive data
        clearKeyBuffer(byteBuffer.array()); // clear sensitive data

        return newSet;
    }

    /**
     * Clean a buffer by writing on it.
     *
     * @since 1.0
     * @param key to be cleaned.
     */
    public static final void clearKeyBuffer(final byte[] key) {
        Arrays.fill(key, (byte) 0);
    }

    /**
     * Clean a buffer by writing on it.
     *
     * @since 1.0
     * @param key to be cleaned.
     */
    public static final void clearKeyBuffer(final BitSet key) {
        key.clear();
    }

    /**
     * Clean a buffer by writing on it.
     *
     * @since 1.0
     * @param key to be cleaned.
     */
    public static final void clearKeyBuffer(final char[] key) {
        Arrays.fill(key, '\u0000');
    }

    /**
     * Write the bytes on the specified array.
     *
     * @since 1.0
     * @param dest
     */
    public void write(byte[] dest) {
        byte[] data = toByteArray();

        System.arraycopy(data, 0, dest, 0, Math.min(dest.length, data.length));

        clearKeyBuffer(data);
    }
}
