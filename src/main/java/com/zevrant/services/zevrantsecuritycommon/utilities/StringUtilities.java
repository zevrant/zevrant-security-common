package com.zevrant.services.zevrantsecuritycommon.utilities;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;

//TODO create pojo utilities library
public class StringUtilities {

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Get hash of file
     *
     * @param digest MessageDigest of the hash type e.g. MessageDigest.getInstance(MessageDigestAlgorithms.SHA_256)
     * @param is     input stream created from file in which to be hashed
     * @return hash of file
     * @throws IOException @see java.io.InputStream.read()
     */
    public static String getChecksum(MessageDigest digest, InputStream is) throws IOException {
        byte[] bytes = new byte[1024];
        while (is.read(bytes) > -1) {
            digest.update(bytes);
        }

        return StringUtilities.bytesToHex(digest.digest());
    }
}
