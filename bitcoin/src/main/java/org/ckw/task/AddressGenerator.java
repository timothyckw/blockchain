package org.ckw.task;

import lombok.extern.slf4j.Slf4j;
import org.bitcoinj.core.*;
import org.bitcoinj.crypto.*;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.wallet.DeterministicKeyChain;
import org.bitcoinj.wallet.DeterministicSeed;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.bitcoinj.params.MainNetParams;
import sun.security.provider.SecureRandom;


import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

@Slf4j
@RestController
public class AddressGenerator {

  private static final MainNetParams MAINNET = MainNetParams.get();
  private static final TestNet3Params TESTNET = TestNet3Params.get();

  @RequestMapping(value = "/getTimeStamp")
  public long getTimeStamp() {
    return Calendar.getInstance().getTimeInMillis();
  }

  @RequestMapping(value = "/getBench12Address")
  public String getBench12Address() throws MnemonicException.MnemonicLengthException {
    NetworkParameters params = MainNetParams.get();
    ECKey ecKey = new ECKey();

    System.out.format("Private Key => %s\n", ecKey.getPrivateKeyAsHex());
    System.out.format("Public Key => %s\n", ecKey.getPublicKeyAsHex());

    SegwitAddress segwitAddress = SegwitAddress.fromKey(MAINNET, ecKey);
    System.out.println("bc1开头的地址：" + segwitAddress.toBech32());

    SecureRandom secureRandom = new SecureRandom();
    byte[] entropy = new byte[DeterministicSeed.DEFAULT_SEED_ENTROPY_BITS / 8];
    secureRandom.engineNextBytes(entropy);

    //生成12位助记词
    List<String>  str = MnemonicCode.INSTANCE.toMnemonic(entropy);
    System.out.println(str);

    String password = "22";
    DeterministicSeed seed = new DeterministicSeed(str, null, password, 0);
    DeterministicKey masterKey = HDKeyDerivation.createMasterPrivateKey(seed.getSeedBytes());
    //    //使用助记词生成钱包种子
//    byte[] seed = MnemonicCode.toSeed(str, "");
//    DeterministicKey masterPrivateKey = HDKeyDerivation.createMasterPrivateKey(seed);
//    DeterministicHierarchy deterministicHierarchy = new DeterministicHierarchy(masterPrivateKey);
//    DeterministicKey deterministicKey = deterministicHierarchy
//            .deriveChild(BIP44_ETH_ACCOUNT_ZERO_PATH, false, true, new ChildNumber(0));
//    byte[] bytes = deterministicKey.getPrivKeyBytes();
//    ECKeyPair keyPair = ECKeyPair.create(bytes);
//    //通过公钥生成钱包地址
//    String address = Keys.getAddress(keyPair.getPublicKey());

    return ecKey.toString();
  }
}
