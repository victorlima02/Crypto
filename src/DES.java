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

import crypto.ciphers.Cipher;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;

/**
 * Assignment 1 - CSS 527 A - Fall 2014 UWB
 *
 * <p>
 * High level modeling for DES encryption algorithm in CBC mode.
 * </p>
 *
 * @author Victor de Lima Soares
 * @version 1.0
 */
public class DES {

    /**
     * Cipher to be used for encryption/decryption operations.
     */
    private static final Cipher des = new crypto.ciphers.block.feistel.des.DES();

    /**
     * Main function to execute the commands passed by command line.
     *
     * @since 1.0
     * @param args Arguments for execution. Options:
     * <ul>
     * <li>genkey password outputFile </li>
     * <li>encrypt inputFile keyFile outputFile </li>
     * <li>decrypt inputFile keyFile outputFile </li>
     * </ul>
     * @throws IOException
     * <ul>
     * <li>If it fails to open, reads or write in any of the files passed as argument.</li>
     * </ul>
     * @throws FileNotFoundException
     * <ul>
     * <li>If it fails to find any of the files passed as argument.</li>
     * </ul>
     * @throws NoSuchAlgorithmException
     * <ul>
     * <li>If it fails to find the UTF-8 encoding algorithm to encode the password string.</li>
     * </ul>
     */
    public static void main(String[] args) throws IOException, FileNotFoundException, NoSuchAlgorithmException {
        switch (args[0]) {
            case "genkey":
                writePassword(args[1], args[2]);
                break;
            case "encrypt":
                encrypt(args[1], args[2], args[3]);
                break;
            case "decrypt":
                decrypt(args[1], args[2], args[3]);
                break;
            default:
                System.err.println("Command not reconized. Options are:");
                System.err.println("genkey password outputFile");
                System.err.println("encrypt inputFile keyFile outputFile");
                System.err.println("decrypt inputFile keyFile outputFile");
        }
    }

    /**
     * Writes a binary file containing a MD5 hash for the password string
     * encoded as utf-8.
     *
     * @since 1.0
     * @param password Password String.
     * @param fileName Output file name.
     * @throws FileNotFoundException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    private static void writePassword(String password, String fileName) throws FileNotFoundException, IOException, NoSuchAlgorithmException {
        try (OutputStream file = new BufferedOutputStream(new FileOutputStream(fileName))) {
            file.write(((crypto.ciphers.block.feistel.des.DES) des).genkey(password.getBytes("UTF-8")));
        }
    }

    /**
     * Reads the password to be used on encryption and decryption.
     *
     * @since 1.0
     * @param passwordFile Password file name.
     * @return The key read.
     *
     * @throws FileNotFoundException
     * @throws IOException
     */
    private static byte[] readKey(String passwordFile) throws FileNotFoundException, IOException {
        try (InputStream file = new BufferedInputStream(new FileInputStream(passwordFile))) {
            byte buffer[] = new byte[8];
            file.read(buffer);
            return buffer;
        }
    }

    /**
     * Encrypts a file, recording the resulting data in the specified file.
     *
     * @since 1.0
     * @param inputFileName Name of the file to be read.
     * @param passwordFile Name for the file that contains the key for
     * encryption.
     * @param outputFileName Name of the output file.
     * @throws IOException
     */
    private static void encrypt(String inputFileName, String passwordFile, String outputFileName) throws IOException {

        try (InputStream input = new BufferedInputStream(new FileInputStream(inputFileName));
                OutputStream output = new BufferedOutputStream(new FileOutputStream(outputFileName))) {
            des.encrypt(input, readKey(passwordFile), output);
        }
    }

    /**
     * Decrypts a file, recording the resulting data in the specified file.
     *
     * @since 1.0
     * @param inputFileName Name of the file to be read.
     * @param passwordFile Name for the file that contains the key for
     * decryption.
     * @param outputFileName Name of the output file.
     * @throws IOException
     */
    private static void decrypt(String inputFileName, String passwordFile, String outputFileName) throws IOException {

        try (InputStream input = new BufferedInputStream(new FileInputStream(inputFileName));
                OutputStream output = new BufferedOutputStream(new FileOutputStream(outputFileName))) {
            des.decrypt(input, readKey(passwordFile), output);
        }
    }

}
