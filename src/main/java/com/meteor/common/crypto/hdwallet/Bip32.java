package com.meteor.common.crypto.hdwallet;


import lombok.Data;
import org.apache.commons.lang3.StringUtils;
import org.bitcoinj.crypto.*;
import org.bitcoinj.wallet.DeterministicSeed;

import java.util.List;

/**
 * @ClassName: Bip32
 * @Description: bip32
 * @author: meteor
 * @createDate: 2021-3-17 14:47
 * <p>
 * ---------------------------------------------------------
 * @Version: v1.0
 */
@Data
public class Bip32 {

    private final byte[] SEED = null;
    private final String PASSPHRASE = "PHJT-DID-MASTER-KEY";
    private final Long CREATIONTIMESECONDS = 0l;

    private DeterministicHierarchy masterWallet;
    private DeterministicKey masterKey;

    /**
     * 需要先生成钱包
     * @param wordList
     * @return
     * @throws Exception
     */
    public Bip32 wallet(String wordList) throws Exception
    {
        // 生成种子
        DeterministicSeed deterministicSeed = new DeterministicSeed(wordList, SEED, PASSPHRASE, CREATIONTIMESECONDS);

        // 生成主私钥
        DeterministicKey rootPrivateKey = HDKeyDerivation.createMasterPrivateKey(deterministicSeed.getSeedBytes());

        // 先生成一个钱包
        masterWallet = new DeterministicHierarchy(rootPrivateKey);
        return this;
    }

    /**
     * 根据钱包生成主私钥
     * @param parentPath
     * @return
     */
    public Bip32 masterKey(String parentPath)
    {
        // 父路径解析
        List<ChildNumber> parsePath = HDUtils.parsePath(parentPath);

        // 根据路径生成主key
        masterKey = masterWallet.get(parsePath, true, true);
        return this;
    }

    /**
     * 强化衍生子私钥
     * @param index
     * @return
     */
    public DeterministicKey deriveChildKey(int index)
    {
       return HDKeyDerivation.deriveChildKey(masterKey, index);
    }

    /**
     * 根据路径推出子私钥
     * @param path
     * @return
     */
    public DeterministicKey deriveChildKeyByPath(String path)
    {
        List<ChildNumber> parsePath = HDUtils.parsePath(path);
        ChildNumber index = parsePath.get(4);
        String[] pathArr = path.split("/");
        String[] parentArr = java.util.Arrays.copyOf(pathArr, 4);

        String pathString = StringUtils.join(parentArr, "/");
        List<ChildNumber> parentPath = HDUtils.parsePath(pathString);
        return masterWallet.deriveChild(parentPath, true, true, index);
    }
}
