package com.meteor.common.crypto.sha3;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.util.encoders.Hex;

/**
 * @Description: SHA3算法
 * @ClassName: Sha3Encrypt
 * @author: meteor
 * @createDate: 2021年04月03日
 * <p>
 * ---------------------------------------------------------
 * Version  v1.0
 */
public class Sha3Encrypt {

    /**
     * SHA3-224 算法
     *
     * @param bytes 加密内容
     * @return hash
     */
    public static String sha3224(byte[] bytes) {
        Digest digest = new SHA3Digest(224);
        digest.update(bytes, 0, bytes.length);
        byte[] rsData = new byte[digest.getDigestSize()];
        digest.doFinal(rsData, 0);
        return Hex.toHexString(rsData);
    }

    /**
     * SHA3-256 算法
     *
     * @param bytes 加密内容
     * @return hash
     */
    public static String sha3256(byte[] bytes) {
        Digest digest = new SHA3Digest(256);
        digest.update(bytes, 0, bytes.length);
        byte[] rsData = new byte[digest.getDigestSize()];
        digest.doFinal(rsData, 0);
        return Hex.toHexString(rsData);
    }

    /**
     * SHA3-384 算法
     *
     * @param bytes 加密内容
     * @return hash
     */
    public static String sha3384(byte[] bytes) {
        Digest digest = new SHA3Digest(384);
        digest.update(bytes, 0, bytes.length);
        byte[] rsData = new byte[digest.getDigestSize()];
        digest.doFinal(rsData, 0);
        return Hex.toHexString(rsData);
    }

    /**
     * SHA3-512 算法
     *
     * @param bytes 加密内容
     * @return hash
     */
    public static String sha3512(byte[] bytes) {
        Digest digest = new SHA3Digest(512);
        digest.update(bytes, 0, bytes.length);
        byte[] rsData = new byte[digest.getDigestSize()];
        digest.doFinal(rsData, 0);
        return Hex.toHexString(rsData);
    }

    /**
     * SHAKE-128 算法
     *
     * @param bytes 加密内容
     * @return hash
     */
    public static String shake128(byte[] bytes) {
        Digest digest = new SHAKEDigest(128);
        digest.update(bytes, 0, bytes.length);
        byte[] rsData = new byte[digest.getDigestSize()];
        digest.doFinal(rsData, 0);
        return Hex.toHexString(rsData);
    }

    /**
     * SHAKE-256 算法
     *
     * @param bytes 加密内容
     * @return hash
     */
    public static String shake256(byte[] bytes) {
        Digest digest = new SHAKEDigest(256);
        digest.update(bytes, 0, bytes.length);
        byte[] rsData = new byte[digest.getDigestSize()];
        digest.doFinal(rsData, 0);
        return Hex.toHexString(rsData);
    }

    /**
     * Keccak-256 算法
     *
     * @param bytes 加密内容
     * @return hash
     */
    public static String keck256(byte[] bytes) {
        Keccak.DigestKeccak digest = new Keccak.Digest256();
        digest.update(bytes, 0, bytes.length);
        return Hex.toHexString(digest.digest());
    }
}
