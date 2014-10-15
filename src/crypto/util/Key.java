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

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.BitSet;

/**
 * A key class implemented as a closeable resource.
 *
 * <p>
 * This key was implemented to be used inside try-with-resource blocks, being
 * automatically cleaned after use, ready to wait for garbage collection.
 * </p>
 *
 * <p>
 * Uses UTF-8.
 * </p>
 *
 * @author Victor de Lima Soares
 * @version 1.0
 */
public final class Key implements AutoCloseable, Cloneable {

    private final BitSet key;

    /**
     * Flag to assure
     */
    private boolean closed = false;

    /**
     * Creates a key from a char[].
     *
     * <p>
     * A new bit set with the char[] argument will be created inside this
     * object, and only the copy hosted on this instance will be cleaned after
     * use - this class has no effect on the original char[].
     * </p>
     *
     * @param key
     */
    public Key(char[] key) {
        this.key = toBitSet(key);
    }

    /**
     * Creates a key from a bit set.
     *
     * <p>
     * A new copy from the bit set will be created inside this object, and only
     * the copy hosted on this instance will be cleaned after use - this class
     * has no effect on the original bis set.
     * </p>
     *
     * @param key
     */
    public Key(BitSet key) {
        this.key = (BitSet) key.clone();
    }

    /**
     * Reads a char[] key and converting into a bit set base key.
     *
     * <p>
     * All used buffers are cleaned before returning, except for the original
     * key, this class will not clean the argument, but it provides other
     * methods to clean it if desired.
     * </p>
     *
     * @since 1.0
     * @param key key to be converted.
     * @return Bit set representing the key.
     */
    private BitSet toBitSet(final char[] key) {

        CharBuffer charBuffer = CharBuffer.wrap(key);
        ByteBuffer byteBuffer = Charset.forName("UTF-8").encode(charBuffer);

        byte[] bytes = Arrays.copyOfRange(byteBuffer.array(),
                byteBuffer.position(), byteBuffer.limit());

        clearKeyBuffer(charBuffer.array()); // clear sensitive data
        clearKeyBuffer(byteBuffer.array()); // clear sensitive data

        BitSet newKey = BitSet.valueOf(bytes);
        clearKeyBuffer(bytes);
        return newKey;
    }

    /**
     * Returns the key bit set (any changes on it will affect the key).
     *
     * @since 1.0
     * @return key bit set
     */
    public final BitSet getKey() {
        return key;
    }

    /**
     * Clean a buffer by writing on it.
     *
     * @since 1.0
     * @param key to be cleaned.
     */
    protected static final void clearKeyBuffer(final byte[] key) {
        Arrays.fill(key, (byte) 0);
    }

    /**
     * Clean a buffer by writing on it.
     *
     * @since 1.0
     * @param key to be cleaned.
     */
    protected static final void clearKeyBuffer(final BitSet key) {
        key.clear();
    }

    /**
     * Clean a buffer by writing on it.
     *
     * @since 1.0
     * @param key to be cleaned.
     */
    protected static final void clearKeyBuffer(final char[] key) {
        Arrays.fill(key, '\u0000');
    }

    /**
     * Clone the Key.
     *
     * <p>
     * It will return a new instance with the same(copied) data.
     * </p>
     *
     * @return
     */
    @Override
    public final Key clone() {
        return new Key(key);
    }

    /**
     * Close this "resource".
     *
     * <p>
     * This method will assure the key is cleaned after its use, if used with a
     * try-with-resource.
     * </p>
     * <p>
     * If try-with-resource block is not used, the key need to be closed
     * manually; e.i., inside a finally block.
     * </p>
     */
    @Override
    public final void close() {
        clearKeyBuffer(key);
        setClosed(true);
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
}
