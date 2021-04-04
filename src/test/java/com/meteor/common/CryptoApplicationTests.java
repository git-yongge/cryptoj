package com.meteor.common;

import com.meteor.common.crypto.CommonApplication;
import com.meteor.common.crypto.aes.AesEncrypt;
import com.meteor.common.crypto.ecdsa.Eckey;
import com.meteor.common.crypto.ecdsa.Signature;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.buf.HexUtils;
import org.bitcoinj.core.ECKey;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.SignatureException;

@Slf4j
@SpringBootTest(classes = CommonApplication.class)
class CryptoApplicationTests {

    @Test
    void contextLoads() {
    }

    @Test
    void aesEncrypt() {
        String data = "111222333";
        String aeskey = "1234567812345678";
        String s = AesEncrypt.encryptWithBase64(data, aeskey);
        log.info("密文：{}", s);

        String s1 = AesEncrypt.decryptWithBase64(s, aeskey);
        log.info("原文：{}", s1);
    }

    @Test
    void generatekey() {

        // 生成私钥
        ECKey key = Eckey.generatekey();

        // 私钥16进制字符串
        String privHex = key.getPrivateKeyAsHex();
        log.info("priv: {}", privHex);

        // 压缩66位公钥
        String pubhex = key.getPublicKeyAsHex();
        log.info("compress: {}", pubhex);

        // 非压缩04打头130位公钥
        String decompressPub = key.decompress().getPublicKeyAsHex();
        log.info("decompress: {}", decompressPub);

        // sha256hash签名
        String msg = "hello world";
        String base64Sign = Signature.sha256HashSign(key, msg);
        log.info("base64Sign: {}", base64Sign);

        // 验签
        try {
            Signature.sha256HashVerify(key, msg, base64Sign);
            log.info("验签成功");
        } catch (Exception e) {
            log.error("Exception: {}", e.getMessage());
        }
    }

    @Test
    void signature() {

        String msg = "hello";
        String keccak256 = Signature.keccak256HashHex(msg.getBytes());
        log.info("keccak256: {}", keccak256);

        // golang SignCompact方法签名结果
        String hexSign = "1b2a3f8181094733ae467c28910690d9019f2b2a2e63a86b57023dfda8bffb2486215445a4bbe4232a16b2dd3623c909bd62fc564d20f4d71f7f34b3251ed2ea9d";
        String hexpriv = "22861a2fbd5c05cf30e86a3370bbbc7d122e83aa4b2530629d14ae6ada41cc7b";
        String hash = "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8";
        byte[] prvByte = HexUtils.fromHexString(hexpriv);
        ECKey priv = ECKey.fromPrivate(prvByte);
        log.info("公钥地址：{}", priv.decompress().getPublicKeyAsHex());

        // java验签
        try {
            ECKey ecKey1 = Signature.signedMessageToKey(hash, hexSign);
            log.info("验签结果：{}", ecKey1.decompress().getPublicKeyAsHex());
        } catch (SignatureException e) {
            log.error("验签失败：{}", e.getMessage());
        }

        // java签名结果与golang签名一致
        String s = Signature.signMessage(hash, priv, false);
        log.info("s: {}", s);
    }

}
