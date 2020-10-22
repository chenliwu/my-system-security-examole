package com.chenlw.example.security.utils;


import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class AesUtilsTest {

    /**
     * 密钥长度为16
     */
    private static final String AES_KEY = "1234567812345678";

    private static final String AES_IV = "1234567812345678";

    @Test
    public void test() {
        try {
            String data = "hello world";
            System.out.println("原文：" + data);
            String encryptData = AesUtils.aesCbcEncrypt(data, AES_KEY, AES_IV, StandardCharsets.UTF_8.name());
            System.out.println("加密后的数据：" + encryptData);
            String decryptData = AesUtils.aesCbcDecrypt(encryptData, AES_KEY, AES_IV, StandardCharsets.UTF_8.name());
            System.out.println("解密后的数据：" + decryptData);
            Assert.assertEquals(data, decryptData);
        } catch (Exception e) {
            System.out.println("异常：" + e.getMessage());
        }
    }

}