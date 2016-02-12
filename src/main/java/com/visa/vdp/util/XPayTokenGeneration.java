package com.visa.vdp.util;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SignatureException;

public class XPayTokenGeneration {

    public static final String SHARED_SECRET = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXx";
            
    public static final String API_KEY="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

    public static String getXPayToken(String apiNameURI, String queryString, String requestBody) throws SignatureException {
        String timestamp = getTimestamp();
        String sourceString = SHARED_SECRET + timestamp + apiNameURI + queryString + requestBody;
        String hash = sha256Digest(sourceString);
        String token = "x:" + timestamp + ":" + hash;
        return token;
    }
    
    private static String getTimestamp() {
        return String.valueOf(System.currentTimeMillis() / 1000L);
    }

    private static String sha256Digest(String data) throws SignatureException {
        return getDigest("SHA-256", data, true);
    }

    private static String getDigest(String algorithm, String data, boolean toLower) throws
            SignatureException {
        try {
            MessageDigest mac = MessageDigest.getInstance(algorithm);
            mac.update(data.getBytes("UTF-8"));
            return toLower
                    ? new String(toHex(mac.digest())).toLowerCase() : new String(toHex(mac.digest()));
        } catch (Exception e) {
            throw new SignatureException(e);
        }
    }

    private static String toHex(byte[] bytes) {
        BigInteger bi = new BigInteger(1, bytes);
        return String.format("%0" + (bytes.length << 1) + "X", bi);
    }
}
