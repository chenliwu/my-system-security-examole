package com.chenlw.example.security.utils;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Assert;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

class SM3UtilsTest {

    @Test
    public void testHashAndVerify() {
        try {
            String data = "SM3UtilsTest";
            byte[] hash = SM3Utils.hash(data.getBytes(StandardCharsets.UTF_8.name()));
            System.out.println("hash:" + Arrays.toString(hash));
            System.out.println("SM3 hash HexString:\n" + ByteUtils.toHexString(hash));
            String hashBase64String = Base64.toBase64String(hash);
            System.out.println("SM3 Base64 String:\n" + hashBase64String);
            System.out.println("hash:\n" + Arrays.toString(Base64.decode(hashBase64String)));
            boolean flag = SM3Utils.verify(data.getBytes(StandardCharsets.UTF_8.name()), hash);
            Assert.assertEquals(true, flag);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

}