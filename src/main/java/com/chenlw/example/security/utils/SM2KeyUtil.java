package com.chenlw.example.security.utils;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * <br>
 * <b>功能：</b>   <br>
 * <b>作者：</b> chenlw <br>
 * <b>日期：</b> 2021-01-15  <br>
 */
public class SM2KeyUtil {

    private static final String CHARSET_NAME = "UTF-8";


    /**
     * 导出公钥和私钥
     *
     * @param privateKeyFilePath 私钥文件路径
     * @param publicKeyFilePath  公钥文件路径
     * @throws Exception 异常
     */
    public static void generatePemFile(String privateKeyFilePath, String publicKeyFilePath) throws Exception {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            byte[] priKeyPkcs8Der = BCECUtil.convertECPrivateKeyToPKCS8(priKey, pubKey);
            String priKeyPkcs8Pem = BCECUtil.convertECPrivateKeyPKCS8ToPEM(priKeyPkcs8Der);
            // 导出私钥到.pem文件
            FileUtil.writeFile(privateKeyFilePath, priKeyPkcs8Pem.getBytes(CHARSET_NAME));

            byte[] pubKeyX509Der = BCECUtil.convertECPublicKeyToX509(pubKey);
            String pubKeyX509Pem = BCECUtil.convertECPublicKeyX509ToPEM(pubKeyX509Der);
            // 导出公钥到.pem文件
            FileUtil.writeFile(publicKeyFilePath, pubKeyX509Pem.getBytes(CHARSET_NAME));
        } catch (Exception e) {
            System.out.println("异常：" + e.getMessage());
            throw new Exception("导出公钥和私钥失败");
        }
    }

    /**
     * 从文件读取私钥
     *
     * @param filePath 文件路径
     * @return 私钥
     * @throws Exception 异常
     */
    public static PrivateKey getPrimaryKey(String filePath) throws Exception {
        try {
            byte[] primaryKeyByte = FileUtil.readFile(filePath);
            String priKeyPerString = new String(primaryKeyByte, CHARSET_NAME);
            // System.out.println(priKeyPerString);
            byte[] priKeyFromPem = BCECUtil.convertECPrivateKeyPEMToPKCS8(priKeyPerString);
            return BCECUtil.convertPKCS8ToECPrivateKey(priKeyFromPem);
        } catch (Exception e) {
            System.out.println("异常：" + e.getMessage());
            throw new Exception("读取私钥失败");
        }
    }

    /**
     * 从文件读取公钥
     *
     * @param filePath 文件路径
     * @return 公钥
     * @throws Exception 异常
     */
    public static PublicKey getPublicKey(String filePath) throws Exception {
        try {
            // 从.pem文件读取公钥
            String pubKeyX509PemString = new String(FileUtil.readFile(filePath), CHARSET_NAME);
//            System.out.println();
//            System.out.println("==========公钥perString=======");
//            System.out.println(pubKeyX509PemString);
            byte[] pubKeyX509Byte = BCECUtil.convertECPublicKeyPEMToX509(pubKeyX509PemString);
            return BCECUtil.convertX509ToECPublicKey(pubKeyX509Byte);
        } catch (Exception e) {
            System.out.println("异常：" + e.getMessage());
            throw new Exception("读取公钥失败");
        }
    }

}
