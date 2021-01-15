package com.chenlw.example.security.utils;

import org.junit.Assert;
import org.junit.Test;

public class SM2KeyUtilTest {

    @Test
    public void testGeneratePemFile() {
        try {
            SM2KeyUtil.generatePemFile("testPrivateKey.sm2.pem", "testPublicKey.sm2.pem");
        } catch (Exception e) {
            System.out.println("异常:" + e.getMessage());
            Assert.fail();
        }
    }





}