package com.meteor.common.crypto.did;

import org.bitcoinj.core.Base58;
import org.bitcoinj.core.Utils;
import org.bouncycastle.util.Strings;

/**
 * @Description: DID
 * @ClassName: DID
 * @author: meteor
 * @createDate: 2021年04月03日
 * <p>
 * ---------------------------------------------------------
 * Version  v1.0
 */
public class DID {

    /**
     * 生成DID
     * @param didDocument
     * @return base58(ripemd160(sha256(<Base DID Document>)))
     */
    public String generateDID(String method, String didDocument)
    {
        byte[] shaHash = Utils.sha256hash160(didDocument.getBytes());
        return Strings.toLowerCase("did:" + method + ":" + Base58.encode(shaHash));
    }
}
