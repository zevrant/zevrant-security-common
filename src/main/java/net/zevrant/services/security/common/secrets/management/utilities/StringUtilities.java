package net.zevrant.services.security.common.secrets.management.utilities;

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
     * Get sha256 has of file
     *
     * @param digest
     * @param is
     * @return
     * @throws IOException
     */
    private static String getChecksum(MessageDigest digest, InputStream is) throws IOException {
        byte[] bytes = new byte[1024];
        while (is.read(bytes) > -1) {
            digest.update(bytes);
        }

        return StringUtilities.bytesToHex(digest.digest());
    }
}
