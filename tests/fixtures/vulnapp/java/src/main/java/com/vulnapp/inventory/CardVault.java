package com.vulnapp.inventory;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class CardVault {
    private static final SecretKeySpec KEY =
            new SecretKeySpec(HexFormat.of().parseHex(System.getenv("VULNAPP_CARD_KEY")), "AES");
    private static final SecureRandom RANDOM = new SecureRandom();

    private CardVault() {
    }

    public static byte[] seal(String number) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, KEY);
        return cipher.doFinal(number.getBytes(StandardCharsets.US_ASCII));
    }

    public static byte[] sealV2(String number) throws GeneralSecurityException {
        byte[] iv = new byte[12];
        RANDOM.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, KEY, new GCMParameterSpec(128, iv));
        byte[] sealed = cipher.doFinal(number.getBytes(StandardCharsets.US_ASCII));
        return ByteBuffer.allocate(iv.length + sealed.length).put(iv).put(sealed).array();
    }
}
