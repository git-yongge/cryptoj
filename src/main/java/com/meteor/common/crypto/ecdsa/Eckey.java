package com.meteor.common.crypto.ecdsa;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.spongycastle.util.encoders.Hex;

/**
 * @Description: 椭圆曲线常用方法封装
 * @ClassName: Eckey
 * @author: meteor
 * @createDate: 2021年04月03日
 * <p>
 * ---------------------------------------------------------
 * Version  v1.0
 */
public class Eckey {

    /**
     * 生成私钥
     * @return
     */
    public static ECKey generatekey() {
        return new ECKey();
    }

    /**
     * 获取私钥字符串
     * @param key
     * @return
     */
    public static String privkeyToHex(ECKey key) {
        return key.getPrivateKeyAsHex();
    }

    /**
     * 字符串转私钥
     * @param privhex
     * @return
     */
    public static ECKey hexToPrivkey(String privhex) {
        byte[] privByte = Hex.decode(privhex);
        return ECKey.fromPrivate(privByte);
    }

    /**
     * 获取公钥130字符串,非压缩
     * @param key
     * @return
     */
    public static String deCompressPubHex(ECKey key) {
        return key.decompress().getPublicKeyAsHex();
    }

    /**
     * 获取66位字符串，压缩
     * @param key
     * @return
     */
    public static String compressPubHex(ECKey key) {
        return key.getPublicKeyAsHex();
    }

    /**
     * 字符串转公钥
     * @param pubhex
     * @return
     */
    public static ECKey hexToPubkey(String pubhex) {
        byte[] privByte = Hex.decode(pubhex);
        return ECKey.fromPublicOnly(privByte);
    }

    /**
     * 获取地址
     * @param key
     * @param parameters MainNetParams.get()|TestNet2Params.get()
     * @return
     */
    public static String getAddress(ECKey key, NetworkParameters parameters) {
        return key.toAddress(parameters).toBase58();
    }
}
