package com.chenlw.example.security.utils;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Assert;
import org.junit.Test;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * <br>
 * <b>功能：</b>   <br>
 * <b>作者：</b> chenlw <br>
 * <b>日期：</b> 2021-01-14  <br>
 */
public class SM2UtilTest {


    @Test
    public void testGetPublicKey() {
        try {
            // PublicKey publicKey = getPublicKey(new FileInputStream("target/ec.pkcs8.pri.pem"),"EC");
            PublicKey publicKey = SM2KeyUtil.getPublicKey("target/ec.pkcs8.pri.pem");
            Assert.assertNotNull(publicKey);
        } catch (Exception e) {
            System.out.println("异常：" + e.getMessage());
            Assert.fail();
        }
    }

    /**
     * 生成.pem证书文件
     */
    @Test
    public void testGeneratePemFile() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            byte[] priKeyPkcs8Der = BCECUtil.convertECPrivateKeyToPKCS8(priKey, pubKey);
            String priKeyPkcs8Pem = BCECUtil.convertECPrivateKeyPKCS8ToPEM(priKeyPkcs8Der);
            // 导出私钥到.pem文件
            FileUtil.writeFile("target/ec.pkcs8.pri.pem", priKeyPkcs8Pem.getBytes("UTF-8"));

            byte[] pubKeyX509Der = BCECUtil.convertECPublicKeyToX509(pubKey);
            String pubKeyX509Pem = BCECUtil.convertECPublicKeyX509ToPEM(pubKeyX509Der);
            // 导出公钥到.pem文件
            FileUtil.writeFile("target/ec.x509.pub.pem", pubKeyX509Pem.getBytes("UTF-8"));
        } catch (Exception e) {
            System.out.println("异常：" + e.getMessage());
            Assert.fail();
        }
    }

    /**
     * 测试从 .pem读取私钥和公钥
     */
    @Test
    public void testGetKeyFromFile() {
        try {
            // 从.pem文件读取私钥
            byte[] primaryKeyByte = FileUtil.readFile("target/ec.pkcs8.pri.pem");
            String priKeyPerString = new String(primaryKeyByte, "UTF-8");
            System.out.println("==========私钥perString==========");
            System.out.println(priKeyPerString);
            byte[] priKeyFromPem = BCECUtil.convertECPrivateKeyPEMToPKCS8(priKeyPerString);
            BCECPrivateKey priKey = BCECUtil.convertPKCS8ToECPrivateKey(priKeyFromPem);
            Assert.assertNotNull(priKey);

            // 从.pem文件读取公钥
            String pubKeyX509PemString = new String(FileUtil.readFile("target/ec.x509.pub.pem"), "UTF-8");
            System.out.println();
            System.out.println("==========公钥perString=======");
            System.out.println(pubKeyX509PemString);
            byte[] pubKeyX509Byte = BCECUtil.convertECPublicKeyPEMToX509(pubKeyX509PemString);
            BCECPublicKey publicKey = BCECUtil.convertX509ToECPublicKey(pubKeyX509Byte);
            Assert.assertNotNull(publicKey);

            String strData = "测试报文数据";
            // 用公钥加密
            byte[] encryptedByteData = SM2Util.encrypt(publicKey, strData.getBytes(StandardCharsets.UTF_8));
            System.out.println("加密后的base64数据:" + Base64.toBase64String(encryptedByteData));

            // 用私钥解密
            byte[] decryptByteData = SM2Util.decrypt(priKey, encryptedByteData);
            System.out.println("解密后的数据：" + new String(decryptByteData, StandardCharsets.UTF_8));
        } catch (Exception e) {
            System.out.println("异常：" + e.getMessage());
            Assert.fail();
        }

    }

    /**
     * 测试从 .pem读取私钥和公钥  签名和验签
     */
    @Test
    public void testGetKeyFromFileToSign() {
        try {
            // 从.pem文件读取私钥
            byte[] primaryKeyByte = FileUtil.readFile("target/ec.pkcs8.pri.pem");
            String priKeyPerString = new String(primaryKeyByte, "UTF-8");
            System.out.println("==========私钥perString==========");
            System.out.println(priKeyPerString);
            byte[] priKeyFromPem = BCECUtil.convertECPrivateKeyPEMToPKCS8(priKeyPerString);
            BCECPrivateKey priKey = BCECUtil.convertPKCS8ToECPrivateKey(priKeyFromPem);
            Assert.assertNotNull(priKey);

            // 从.pem文件读取公钥
            String pubKeyX509PemString = new String(FileUtil.readFile("target/ec.x509.pub.pem"), "UTF-8");
            System.out.println();
            System.out.println("==========公钥perString=======");
            System.out.println(pubKeyX509PemString);
            byte[] pubKeyX509Byte = BCECUtil.convertECPublicKeyPEMToX509(pubKeyX509PemString);
            BCECPublicKey publicKey = BCECUtil.convertX509ToECPublicKey(pubKeyX509Byte);
            Assert.assertNotNull(publicKey);

            String srcData = "测试报文数据";
            // 签名
            byte[] sign = SM2Util.sign(priKey, srcData.getBytes(StandardCharsets.UTF_8));
            System.out.println("SM2 sign without withId result:\n" + ByteUtils.toHexString(sign));
            // 签名验证
            boolean flag = SM2Util.verify(publicKey, srcData.getBytes(StandardCharsets.UTF_8), sign);
            if (!flag) {
                Assert.fail("verify failed");
            }
        } catch (Exception e) {
            System.out.println("异常：" + e.getMessage());
            Assert.fail();
        }

    }

    /**
     * 测试从 .pem读取私钥和公钥  签名和验签
     */
    @Test
    public void testGetKeyFromFileToSign_1() {
        try {
//            PrivateKey priKey = SM2KeyUtil.getPrimaryKey("target/ec.pkcs8.pri.pem");
//            PublicKey publicKey = SM2KeyUtil.getPublicKey("target/ec.x509.pub.pem");

            PrivateKey priKey = SM2KeyUtil.getPrimaryKey(new FileInputStream("target/ec.pkcs8.pri.pem"));
            PublicKey publicKey = SM2KeyUtil.getPublicKey(new FileInputStream("target/ec.x509.pub.pem"));

            String srcData = "测试报文数据";
            // 签名
            byte[] sign = SM2Util.sign((BCECPrivateKey) priKey, srcData.getBytes(StandardCharsets.UTF_8));
            System.out.println("SM2 sign without withId result:\n" + ByteUtils.toHexString(sign));
            // 签名验证
            boolean flag = SM2Util.verify((BCECPublicKey) publicKey, srcData.getBytes(StandardCharsets.UTF_8), sign);
            if (!flag) {
                Assert.fail("verify failed");
            }
        } catch (Exception e) {
            System.out.println("异常：" + e.getMessage());
            Assert.fail();
        }

    }


}
