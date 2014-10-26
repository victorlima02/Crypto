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
package crypto.ciphers.block.feistel;

import crypto.ciphers.Cipher;
import crypto.util.BitBuffer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.ThreadLocalRandom;

/**
 * A Feistel cipher is a cipher that is modeled in accordance with the Feistel
 * network structure.
 * <p>
 * It is composed by encryption rounds after an initial permutation (IP) and
 * followed by a final permutation (IP<sup>-1</sup>). Following those steps:
 * </p>
 * <ul>
 * <li>IP: the 64 bits block goes through an initial permutation;</li>
 * <li>The resulting block is split into two halves: L<sub>0</sub> and
 * R<sub>0</sub> (inputs for the Feistel network);</li>
 * <li>Rounds of:
 * <ul>
 * <li> R<sub>i</sub> as input to a function f(R<sub>i</sub>,key<sub>i</sub>),
 * with the result being XORed with L<sub>i</sub>; </li>
 * <li> Exchanging L<sub>i+1</sub> for R<sub>i</sub> and R<sub>i+1</sub> for
 * f(R<sub>i</sub>,key<sub>i</sub>) XOR L<sub>i</sub>;</li>
 * </ul>
 * </li>
 * <li>Final permutation: inverse of the initial permutation.</li>
 * </ul>
 * The basic properties, confusion and diffusion, should come from a
 * well-designed function <i>f</i>. Once <i>f</i> has been designed in a secure
 * fashion, the security provided by the Feistel network will increase with the
 * key length and number of rounds.
 *
 * @author Victor de Lima Soares
 * @version 1.0
 */
public abstract class FeistelCipher extends Cipher {

    private final int nRounds;
    private final int blockSize;

    /**
     * Build the Cipher with an specific number of rounds.
     *
     * @param nRounds Number of rounds in the Feistel network.
     * @param blockSize Block size used by the Cipher.
     *
     * @throws IllegalArgumentException
     * <ul>
     * <li>If the number of rounds is less than 0;</li>
     * <li>If the block size is less than 0.</li>
     * </ul>
     */
    public FeistelCipher(int nRounds, int blockSize) {
        if (nRounds <= 0) {
            throw new IllegalArgumentException("Number of rounds must to be greater than 0.");
        }
        if (blockSize <= 0) {
            throw new IllegalArgumentException("Block size must to be greater than 0.");
        }
        this.nRounds = nRounds;
        this.blockSize = blockSize;
    }

    /**
     * Cipher specific initial permutation (IP).
     *
     * @since 1.0
     * @param cipherText Initial ciphertext, a copy of the original message.
     */
    protected abstract void initialPermutation(final BitBuffer cipherText);

    /**
     * Return the key to be used on the current round.
     *
     * @since 1.0
     * @param round Round index.
     * @param keyBuffer Buffer to store state dependent keys, if necessary old
     * keys can be stored, manipulated and returned true this buffer.
     * @return Round key.
     */
    protected abstract BitBuffer getRoundKey(final BitBuffer keyBuffer, int round);

    /**
     * Return the key to be used on the current round, for decryption.
     *
     * @since 1.0
     * @param round Round index.
     * @param keyBuffer Buffer to store state dependent keys, if necessary old
     * keys can be stored, manipulated and returned true this buffer.
     * @return Round key.
     */
    protected abstract BitBuffer getRoundKeyDescryption(BitBuffer keyBuffer, int round);

    /**
     * Cipher specific fFunction.
     *
     * @since 1.0
     * @param right The right half of the encryption block for this round.
     * @param roundKey Round key.
     * @return Resultant bit set from the Cipher f-function.
     */
    protected abstract BitBuffer fFunction(final BitBuffer right, final BitBuffer roundKey);

    /**
     * Cipher specific final permutation (IP<sup>-1</sup>).
     *
     * <p>
     * This permutation should be the inverse of IP.
     * </p>
     *
     * @since 1.0
     * @param cipherText Message after all rounds.
     *
     * @see #initialPermutation(crypto.util.BitBuffer)
     */
    protected abstract void finalPermutation(final BitBuffer cipherText);

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
     *
     * @see crypto.ciphers.Cipher#encrypt(java.io.InputStream, byte[],
     * java.io.OutputStream)
     */
    @Override
    public final void encrypt(final InputStream message, final byte[] key, final OutputStream output) throws IOException {

        if (message == null) {
            throw new NullPointerException("Message cannot be encrypted: message is a reference to null.");
        }
        if (key == null) {
            throw new NullPointerException("Message cannot be encrypted: key is a reference to null.");
        }

        try (BitBuffer keyBuffer = new BitBuffer(key)) {

            BitBuffer cipherBlock;
            byte[] buffer = new byte[getBlockSize() / Byte.SIZE];
            int bytesRead = message.read(buffer);

            cipherBlock = getIV();
            recordIV(cipherBlock, output);

            while (bytesRead > 0) {

                if (bytesRead < 8) {
                    pad(buffer, bytesRead);
                }

                try (BitBuffer readBuffer = BitBuffer.valueOf(buffer)) {
                    readBuffer.xor(cipherBlock);
                    cipherBlock.close();
                    cipherBlock = encryptBlock(readBuffer, keyBuffer);
                    output.write(cipherBlock.toByteArray(8));
                }
                bytesRead = message.read(buffer);
            }
        }
    }

    /**
     * Decrypts the message.
     *
     * @since 1.0
     * @param message Message(cleartext) to be decrypted.
     * @param key Encryption key.
     * @param output Opened OutputStream to record the decrypted data.
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
     *
     * @see crypto.ciphers.Cipher#decrypt(java.io.InputStream, byte[],
     * java.io.OutputStream)
     */
    @Override
    public final void decrypt(final InputStream message, final byte[] key, final OutputStream output) throws IOException {

        if (message == null) {
            throw new NullPointerException("Message cannot be encrypted: message is a reference to null.");
        }
        if (key == null) {
            throw new NullPointerException("Message cannot be encrypted: key is a reference to null.");
        }

        try (BitBuffer keyBuffer = new BitBuffer(key)) {

            BitBuffer plainText;
            BitBuffer readBuffer;
            byte[] buffer = new byte[getBlockSize() / Byte.SIZE];

            plainText = readIV(message);

            int bytesRead = message.read(buffer);

            while (bytesRead > 0) {

                readBuffer = BitBuffer.valueOf(buffer);
                bytesRead = message.read(buffer);

                try (BitBuffer decrypted = decryptBlock(readBuffer, keyBuffer)) {
                    plainText.xor(decrypted);

                    if (bytesRead <= 0) {
                        unPad(plainText);
                    }

                    output.write(plainText.toByteArray(8));
                    plainText.close();
                    plainText = readBuffer;
                }
            }

            plainText.close();
        }
    }

    /**
     * Encrypts a single block.
     *
     * @param block Block to be encrypted.
     * @param key Original key - this key cannot be modified inside this
     * function.
     * @return Encrypted block.
     */
    public final BitBuffer encryptBlock(final BitBuffer block, final BitBuffer key) {

        BitBuffer cipherText = (BitBuffer) block.clone();
        try (BitBuffer keyBuffer = (BitBuffer) key.clone()) {

            initialPermutation(cipherText);

            BitBuffer left = cipherText.get(0, getBlockSize() / 2);
            BitBuffer right = cipherText.get(getBlockSize() / 2, getBlockSize());

            for (int round = 0; round < getNRounds(); round++) {
                round(left, right, getRoundKey(keyBuffer, round));
            }

            for (int i = 0; i < getBlockSize() / 2; i++) {
                boolean tmp = left.get(i);
                left.set(i, right.get(i));
                right.set(i, tmp);
            }

            cipherText.overwrite(0, left, getBlockSize() / 2);
            cipherText.overwrite(getBlockSize() / 2, right, getBlockSize() / 2);

            finalPermutation(cipherText);
            return cipherText;
        }
    }

    /**
     * Decrypts a single block.
     *
     * @param block Block to be decrypted.
     * @param key Original key - this key cannot be modified inside this
     * function.
     * @return Decrypted block.
     */
    public final BitBuffer decryptBlock(final BitBuffer block, final BitBuffer key) {

        BitBuffer plainText = (BitBuffer) block.clone();
        try (BitBuffer keyBuffer = (BitBuffer) key.clone()) {

            initialPermutation(plainText);

            BitBuffer left = plainText.get(0, getBlockSize() / 2);
            BitBuffer right = plainText.get(getBlockSize() / 2, getBlockSize());

            for (int round = 0; round < getNRounds(); round++) {
                round(left, right, getRoundKeyDescryption(keyBuffer, round));
            }

            for (int i = 0; i < getBlockSize() / 2; i++) {
                boolean tmp = left.get(i);
                left.set(i, right.get(i));
                right.set(i, tmp);
            }

            plainText.overwrite(0, left, getBlockSize() / 2);
            plainText.overwrite(getBlockSize() / 2, right, getBlockSize() / 2);

            finalPermutation(plainText);
            return plainText;
        }
    }

    /**
     * Execute one round in the Feisel network.
     *
     * @since 1.0
     * @param left Left block.
     * @param right Right block.
     * @param roundKey Round key.
     */
    protected final void round(final BitBuffer left, final BitBuffer right, final BitBuffer roundKey) {
        left.xor(fFunction(right, roundKey));

        for (int i = 0; i < getBlockSize() / 2; i++) {
            boolean tmp = left.get(i);
            left.set(i, right.get(i));
            right.set(i, tmp);
        }
    }

    /**
     * Returns the number of rounds in the Feistel network.
     *
     * @since 1.0
     * @return Number of rounds.
     */
    public final int getNRounds() {
        return nRounds;
    }

    /**
     * Returns the block size used by the Cipher.
     *
     * @since 1.0
     * @return Block size.
     */
    public final int getBlockSize() {
        return blockSize;
    }

    /**
     * Pad a buffer for completing the 8 bytes total.
     *
     * @since 1.0
     * @param buffer Buffer to be padded.
     * @param nRead Number of bytes read before padding operation.
     */
    protected void pad(byte[] buffer, int nRead) {
        byte n = (byte) (8 - nRead);
        for (int i = nRead; i < 8; i++) {
            buffer[i] = n;
        }
    }

    /**
     * Unpad a buffer padded for completing the 8 bytes total.
     *
     * @since 1.0
     * @param buffer Buffer to be unpadded.
     */
    protected void unPad(BitBuffer buffer) {
        byte[] data = buffer.toByteArray();

        if (data[7] < 8) {
            byte n = data[7];

            int count = 0;

            for (int i = 7; i > 0; i--) {
                if (data[i] == n) {
                    count++;
                }
            }
            if (count == n) {

                byte newData[] = new byte[8 - n];
                System.arraycopy(data, 0, newData, 0, newData.length);

                try (BitBuffer newBuffer = BitBuffer.valueOf(newData)) {
                    buffer.replace(newBuffer);
                    BitBuffer.clearKeyBuffer(newData);
                }
            }
        }

        BitBuffer.clearKeyBuffer(data);
    }

    /**
     * Returns a new initialization vector.
     *
     * @since 1.0
     * @return IV Initialization Vector
     */
    protected BitBuffer getIV() {
        byte iv[] = new byte[8];
        ThreadLocalRandom.current().nextBytes(iv);
        BitBuffer ivBuffer = new BitBuffer(iv);
        BitBuffer.clearKeyBuffer(iv);
        return ivBuffer;
    }

    /**
     * Record IV on a file.
     *
     * @since 1.0
     * @param IV Initialization Vector to be recorded.
     * @param file Destine file.
     * @throws IOException
     * <ul>
     * <li>If it fails to open, reads or write in any of the files passed as
     * argument.</li>
     * </ul>
     */
    protected void recordIV(BitBuffer IV, OutputStream file) throws IOException {
        byte[] data = IV.toByteArray();
        file.write(data);
        BitBuffer.clearKeyBuffer(data);
    }

    /**
     * Read IV on a file.
     *
     * @return iv
     * @since 1.0
     * @param file File to read.
     * @throws IOException
     * <ul>
     * <li>If it fails to open, reads or write in any of the files passed as argument.</li>
     * </ul>
     */
    protected BitBuffer readIV(InputStream file) throws IOException {
        byte[] iv = new byte[getBlockSize() / Byte.SIZE];
        file.read(iv);
        BitBuffer ivBitBuffer = BitBuffer.valueOf(iv);
        BitBuffer.clearKeyBuffer(iv);
        return ivBitBuffer;
    }
}
