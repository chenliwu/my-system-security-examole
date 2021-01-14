package com.chenlw.example.security.utils;

import org.junit.Assert;
import org.junit.Test;

import java.io.FileInputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * <br>
 * <b>功能：</b>   <br>
 * <b>作者：</b> chenlw <br>
 * <b>日期：</b> 2021-01-14  <br>
 */
public class SM2UtilsTest {

    @Test
    public void testGetPublicKey() {
        try {
            //调用方公钥
            PublicKey publicKey = MySM2Utils
                    .getPublicKey(new FileInputStream("D:/ssl/to_czbank_public_key_2048.pem"), "RSA");
            Assert.assertNotNull(publicKey);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            Assert.fail();
        }

    }

    @Test
    public void testGetPrimateKey() {
        try {
            //调用方私钥
            PrivateKey privateKey = MySM2Utils
                    .getPrivateKey(new FileInputStream("D:/ssl/to_czbank_private_key_2048.pem"), "RSA");
            Assert.assertNotNull(privateKey);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            Assert.fail();
        }

    }

}
