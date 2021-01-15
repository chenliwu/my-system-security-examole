package com.chenlw.example.security.utils;

import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 * <br>
 * <b>功能：</b>   <br>
 * <b>作者：</b> chenlw <br>
 * <b>日期：</b> 2021-01-14  <br>
 */
public class MySM2JavaStandardApiUtils {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * 生成密钥对
     *
     * @return
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    public static KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        // 获取SM2椭圆曲线的参数
        final ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
        // 获取一个椭圆曲线类型的密钥对生成器
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        // 使用SM2参数初始化生成器
        kpg.initialize(sm2Spec);
        // 使用SM2的算法区域初始化密钥生成器
        kpg.initialize(sm2Spec, new SecureRandom());
        // 获取密钥对
        return kpg.generateKeyPair();
    }



    public static void testSign() {
        try {
            KeyPair keyPair = generateKeyPair();
            // 获取公私钥
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // 生成SM2sign with sm3 签名验签算法实例
            System.out.println("algorithm:" + GMObjectIdentifiers.sm2sign_with_sm3.toString());
            Signature signature = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), new BouncyCastleProvider());

            // 签名需要使用私钥，使用私钥 初始化签名实例
            signature.initSign(privateKey);
            // 签名原文
            byte[] plainText = "Hello world".getBytes(StandardCharsets.UTF_8);
            // 写入签名原文到算法中
            signature.update(plainText);
            // 计算签名值
            byte[] signatureValue = signature.sign();
            System.out.println("signature: \n" + Hex.toHexString(signatureValue));

            /*
             * 验签
             */
            // 签名需要使用公钥，使用公钥 初始化签名实例
            signature.initVerify(publicKey);
            // 写入待验签的签名原文到算法中
            signature.update(plainText);
            // 验签
            System.out.println("Signature verify result: " + signature.verify(signatureValue));
        } catch (Exception e) {
            System.out.println("异常：" + e.getMessage());
        }

    }

    public static void main(String[] args) {
        testSign();
    }
}
