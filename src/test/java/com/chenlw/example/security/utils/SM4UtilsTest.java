package com.chenlw.example.security.utils;


import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class SM4UtilsTest {

    @Test
    public void testCustomKeySM4ECB() throws Exception {
        String charset = StandardCharsets.UTF_8.name();
        // SM4密钥长度分组长度128bit，因此密匙长度为16
        String myKey = "1234567812345678";
        String data = "SM4UtilsTest";
        byte[] myKeyBytes = myKey.getBytes(charset);
        byte[] encryptedBytes = SM4Utils.encrypt_ECB_Padding(myKeyBytes, data.getBytes(charset));
        String encryptedHexString = ByteUtils.toHexString(encryptedBytes);
        System.out.println("ECB加密后的数据HexString：" + encryptedHexString);
        byte[] decryptedBytes = SM4Utils.decrypt_ECB_Padding(myKeyBytes, ByteUtils.fromHexString(encryptedHexString));
        System.out.println("ECB解密后的数据：" + new String(decryptedBytes, charset));
    }

    @Test
    public void testCustomKeySM4CBC() throws Exception {
        String charset = StandardCharsets.UTF_8.name();
        // SM4密钥长度分组长度128bit，因此密匙长度为16
        String myKey = "1234567812345678";
        String myIv = "8765432187654321";
        String data = "SM4UtilsTest";
        byte[] myKeyBytes = myKey.getBytes(charset);
        byte[] myIvBytes = myIv.getBytes(charset);
        byte[] encryptedBytes = SM4Utils.encrypt_CBC_Padding(myKeyBytes, myIvBytes, data.getBytes(charset));
        String encryptedHexString = ByteUtils.toHexString(encryptedBytes);
        System.out.println("CBC加密后的数据HexString：" + encryptedHexString);
        byte[] decryptedBytes = SM4Utils.decrypt_CBC_Padding(myKeyBytes, myIvBytes, ByteUtils.fromHexString(encryptedHexString));
        System.out.println("CBC解密后的数据：" + new String(decryptedBytes, charset));
    }

}