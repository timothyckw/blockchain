package org.ckw.task;

import lombok.extern.slf4j.Slf4j;
import org.bitcoinj.core.*;
import org.bitcoinj.crypto.*;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.wallet.DeterministicKeyChain;
import org.bitcoinj.wallet.DeterministicSeed;
import org.ckw.bean.Account;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.bitcoinj.params.MainNetParams;
import sun.security.provider.SecureRandom;

import java.math.BigInteger;
import java.util.Calendar;
import java.util.List;

import static org.bitcoinj.crypto.HDUtils.*;

@Slf4j
@RestController
public class AddressGenerator {

  private static final MainNetParams MAINNET = MainNetParams.get();
  private static final TestNet3Params TESTNET = TestNet3Params.get();

  @RequestMapping(value = "/getTimeStamp")
  public long getTimeStamp() {
    return Calendar.getInstance().getTimeInMillis();
  }

  @RequestMapping(value = "/getSegwitAddress")
  public String getBench12Address() throws MnemonicException.MnemonicLengthException {
    NetworkParameters params = MainNetParams.get();
    ECKey ecKey = new ECKey();

    System.out.format("Private Key => %s\n", ecKey.getPrivateKeyAsHex());
    System.out.format("Public Key => %s\n", ecKey.getPublicKeyAsHex());

    SegwitAddress segwitAddress = SegwitAddress.fromKey(MAINNET, ecKey);
    System.out.println("P2WPKH address ：" + segwitAddress.toBech32());

    return ecKey.toString();
  }

  @RequestMapping(value = "/getP2WPKHAddress")
  public Account getP2WPKHAddress() throws MnemonicException.MnemonicLengthException {
    Account account = new Account();

    SecureRandom secureRandom = new SecureRandom();
    byte[] entropy = new byte[DeterministicSeed.DEFAULT_SEED_ENTROPY_BITS / 8];
    secureRandom.engineNextBytes(entropy);
    List<String> mnemonic = MnemonicCode.INSTANCE.toMnemonic(entropy);

    String path = "M/84/0/0/0";
    DeterministicSeed deterministicSeed = new DeterministicSeed(mnemonic, null, "", 0L);
    DeterministicKeyChain deterministicKeyChain = DeterministicKeyChain.builder().seed(deterministicSeed).build();
    BigInteger privateKey = deterministicKeyChain
            .getKeyByPath(parsePath(path), true).getPrivKey();

    ECKey ecKey = ECKey.fromPrivate(privateKey);
    SegwitAddress segwitAddress = SegwitAddress.fromKey(MAINNET, ecKey);
    LegacyAddress legacyAddress = LegacyAddress.fromKey(MAINNET, ecKey);

    account.setPublicKey(ecKey.getPublicKeyAsHex());
    account.setPrivateKey(ecKey.getPrivateKeyAsHex());
    account.setSegwitAddress(segwitAddress.toBech32());
    account.setLegacyAddress(legacyAddress.toBase58());
    account.setMnemonicCode(mnemonic);

    // debug
    System.out.println("--");
    for (int i = 0; i < mnemonic.size(); ++i) {
      System.out.print(mnemonic.get(i) + " ");
    }
    System.out.println("\n--");
    System.out.println(ecKey.getPrivateKeyAsHex());
    System.out.println(ecKey.getPublicKeyAsHex());
    System.out.println("P2WPKH address ：" + segwitAddress.toBech32());
    System.out.println("Legacy address ：" + legacyAddress.toBase58());

    return account;
  }
}
