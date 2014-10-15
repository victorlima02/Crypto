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
package crypto.ciphers;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 *
 * @author Victor de Lima Soares
 * @version 1.0
 */
@FunctionalInterface
public interface Encryptor {

    /**
     * Encrypts the message.
     *
     * @since 1.0
     * @param message Message(cleartext) to be encrypted.
     * @param key Encryption key.
     * @param output Opened OutputStream to record the encrypted data.
     *
     * @throws NullPointerException
     * <ul>
     * <li>If the message is a reference to null;</li>
     * <li>If the key is a reference to null.</li>
     * </ul>
     *
     * @throws IOException
     * <ul>
     * <li>If fails to read the input;</li>
     * <li>If fails to write at the output.</li>
     * </ul>
     */
    public void encrypt(final InputStream message, final byte[] key, final OutputStream output) throws IOException;
}
