package com.meteor.common.crypto.ecdsa;

import com.google.common.base.Preconditions;
import lombok.extern.slf4j.Slf4j;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.KeyCrypterException;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.asn1.x9.X9IntegerConverter;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.signers.ECDSASigner;
import org.spongycastle.crypto.signers.HMacDSAKCalculator;
import org.spongycastle.math.ec.ECAlgorithms;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.custom.sec.SecP256K1Curve;
import org.spongycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.SignatureException;
import java.util.Arrays;

/**
 * @ClassName: Signature
 * @Description: 签名验签方法封装
 * @author: meteor
 * @createDate: 2021年03月31
 * <p>
 * ---------------------------------------------------------
 * @Version: v1.0
 */
@Slf4j
public class Signature {

    public static ECDomainParameters CURVE;

    static {
        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        CURVE = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
    }

    /**
     * signMessage
     * @param message Keccak256哈希hex
     * @param priv 私钥
     * @param compress 是否是压缩公钥
     * @return
     * @throws KeyCrypterException
     */
    public static String signMessage(String message, ECKey priv, boolean compress) throws KeyCrypterException {
        byte[] hash = Hex.decode(message);
        ECKey.ECDSASignature sig = doSign(hash, priv.getPrivKey());
        int recId = -1;

        int headerByte;
        for(headerByte = 0; headerByte < 4; ++headerByte) {
            ECKey k = recoverFromSignature(headerByte, sig, hash, compress);
            if (k != null && k.getPubKeyPoint().equals(priv.getPubKeyPoint())) {
                recId = headerByte;
                break;
            }
        }

        if (recId == -1) {
            throw new RuntimeException("Could not construct a recoverable key. This should never happen.");
        } else {
            headerByte = recId + 27 + (compress ? 4 : 0);
            byte[] sigData = new byte[65];
            sigData[0] = (byte)headerByte;
            System.arraycopy(Utils.bigIntegerToBytes(sig.r, 32), 0, sigData, 1, 32);
            System.arraycopy(Utils.bigIntegerToBytes(sig.s, 32), 0, sigData, 33, 32);
            return new String(Hex.encode(sigData), Charset.forName("UTF-8"));
        }
    }

    /**
     * 根据签名hex转公钥，支持与golang互验
     * @param message keccak256哈希字符串
     * @param signatureHex 不带v的签名哈希字符串
     * @return
     * @throws SignatureException
     */
    public static ECKey signedMessageToKey(String message, String signatureHex) throws SignatureException {
        byte[] signatureEncoded;
        try {
            signatureEncoded = Hex.decode(signatureHex);
        } catch (RuntimeException e) {
            // This is what you get back from Bouncy Castle if base64 doesn't decode :(
            throw new SignatureException("Could not decode base64", e);
        }
        // Parse the signature bytes into r/s and the selector value.
        if (signatureEncoded.length < 65)
            throw new SignatureException("Signature truncated, expected 65 bytes and got " + signatureEncoded.length);


        int header = (byte) signatureEncoded[0] & 0xFF;
        // The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
        //                  0x1D = second key with even y, 0x1E = second key with odd y
        if (header < 27 || header > 34)
            throw new SignatureException("Header byte out of range: " + header);

        BigInteger r = new BigInteger(1, Arrays.copyOfRange(signatureEncoded, 1, 33));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signatureEncoded, 33, 65));
        ECKey.ECDSASignature sig = new ECKey.ECDSASignature(r, s);

        boolean compressed = false;
        if (header >= 31) {
            compressed = true;
            header -= 4;
        }
        int recId = header - 27;
        ECKey key = recoverFromSignature(recId, sig, Hex.decode(message), compressed);
        if (key == null)
            throw new SignatureException("Could not recover public key from signature");
        return key;
    }

    /**
     * Sha256Hash签名
     * @param key
     * @param message
     * @return base64string
     */
    public static String sha256HashSign(ECKey key, String message) {
        return key.signMessage(message);
    }

    /**
     * base64签名校验
     * @param key
     * @param message
     * @param base64Sign
     * @throws SignatureException
     */
    public static void sha256HashVerify(ECKey key, String message, String base64Sign) throws SignatureException {
        key.verifyMessage(message, base64Sign);
    }

    // keccek256哈希byte[]
    public static byte[] keccak256Hash(byte[] b) {
        return new Keccak.Digest256().digest(b);
    }

    // keccek256哈希hex
    public static String keccak256HashHex(byte[] b) {
        return Hex.toHexString(new Keccak.Digest256().digest(b));
    }

    /**
     * Sha256Hash
     * @param message
     * @return
     */
    public static Sha256Hash sha256Hash(String message) {
        byte[] messageBytes = Utils.formatMessageForSigning(message);
        return Sha256Hash.twiceOf(messageBytes);
    }

    /**
     * doSign
     * @param message
     * @param privateKeyForSigning
     * @return
     */
    private static ECKey.ECDSASignature doSign(byte[] message, BigInteger privateKeyForSigning) {
        Preconditions.checkNotNull(privateKeyForSigning);
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(privateKeyForSigning, CURVE);
        signer.init(true, privKey);
        BigInteger[] components = signer.generateSignature(message);
        return (new ECKey.ECDSASignature(components[0], components[1])).toCanonicalised();
    }

    /**
     * 恢复公钥
     * @param recId
     * @param sig
     * @param messageHash
     * @param compressed
     * @return
     */
    private static ECKey recoverFromSignature(int recId, ECKey.ECDSASignature sig, byte[] messageHash, boolean compressed) {
        Preconditions.checkArgument(recId >= 0, "recId must be positive");
        Preconditions.checkArgument(sig.r.signum() >= 0, "r must be positive");
        Preconditions.checkArgument(sig.s.signum() >= 0, "s must be positive");
        Preconditions.checkNotNull(messageHash);
        BigInteger n = CURVE.getN();
        BigInteger i = BigInteger.valueOf((long)recId / 2L);
        BigInteger x = sig.r.add(i.multiply(n));
        BigInteger prime = SecP256K1Curve.q;
        if (x.compareTo(prime) >= 0) {
            return null;
        } else {
            ECPoint R = decompressKey(x, (recId & 1) == 1);
            if (!R.multiply(n).isInfinity()) {
                return null;
            } else {
                BigInteger e = new BigInteger(1, messageHash);;
                BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
                BigInteger rInv = sig.r.modInverse(n);
                BigInteger srInv = rInv.multiply(sig.s).mod(n);
                BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
                ECPoint q = ECAlgorithms.sumOfTwoMultiplies(CURVE.getG(), eInvrInv, R, srInv);
                return ECKey.fromPublicOnly(q.getEncoded(compressed));
            }
        }
    }

    /**
     * 根据大数转坐标
     * @param xBN
     * @param yBit
     * @return
     */
    private static ECPoint decompressKey(BigInteger xBN, boolean yBit) {
        X9IntegerConverter x9 = new X9IntegerConverter();
        byte[] compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(CURVE.getCurve()));
        compEnc[0] = (byte)(yBit ? 3 : 2);
        return CURVE.getCurve().decodePoint(compEnc);
    }
}
