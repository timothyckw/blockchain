package org.ckw.task;

import lombok.extern.slf4j.Slf4j;
import org.bitcoinj.core.*;
import org.bitcoinj.crypto.*;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.wallet.DeterministicKeyChain;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.params.MainNetParams;
import sun.security.provider.SecureRandom;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.ckw.bean.Account;
import org.ckw.bean.MultiSignAccount;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import static org.bitcoinj.crypto.HDUtils.*;

@Slf4j
@RestController
public class AddressGenerator {

  private static final MainNetParams MAIN_NET = MainNetParams.get();
  private static final TestNet3Params TEST_NET = TestNet3Params.get();
  private static final int MAX_EC_KEY_SIZE = 16;
  private static final int THRESHOLD = 2;

  @RequestMapping(value = "/getTimeStamp")
  public long getTimeStamp() {
    return Calendar.getInstance().getTimeInMillis();
  }

  @RequestMapping(value = "/getECKey")
  public String getECKey() {
    ECKey ecKey = new ECKey();
    log.info(ecKey.toString());
    return ecKey.toString();
  }

  @RequestMapping(value = "/getAccount")
  public synchronized Account getAccount() throws MnemonicException.MnemonicLengthException {
    // init account
    Account account = new Account();

    // generate random mnemonic
    SecureRandom secureRandom = new SecureRandom();
    byte[] entropy = new byte[DeterministicSeed.DEFAULT_SEED_ENTROPY_BITS / 8];
    secureRandom.engineNextBytes(entropy);
    List<String> mnemonic = MnemonicCode.INSTANCE.toMnemonic(entropy);

    String path = "M/84/0/0/0/0";
    DeterministicSeed deterministicSeed = new DeterministicSeed(mnemonic, null, "", 0L);
    DeterministicKeyChain deterministicKeyChain = DeterministicKeyChain.builder().seed(deterministicSeed).build();
    BigInteger privateKey = deterministicKeyChain.getKeyByPath(parsePath(path), true).getPrivKey();
    ECKey ecKey = ECKey.fromPrivate(privateKey);
    SegwitAddress segwitAddress = SegwitAddress.fromKey(MAIN_NET, ecKey);
    LegacyAddress legacyAddress = LegacyAddress.fromKey(MAIN_NET, ecKey);

    // update account
    account.setPublicKey(ecKey.getPublicKeyAsHex());
    account.setPrivateKey(ecKey.getPrivateKeyAsHex());
    account.setSegWitAddress(segwitAddress.toBech32());
    account.setLegacyAddress(legacyAddress.toBase58());
    account.setMnemonicCode(mnemonic);
    log.info(account.toString());

    return account;
  }

  @RequestMapping(value = "/getMultiSignAccount")
  public synchronized MultiSignAccount getMultiSignAccount() {
    // create a 2-of-3 multi sign redeemScript (output script)
    List<ECKey> keys = generateECKeys(3);

    if (keys != null) {
      // init multi sign account
      MultiSignAccount multiSignAccount = new MultiSignAccount();

      // create scrip for generate legacy address
      Script redeemScript = ScriptBuilder.createRedeemScript(THRESHOLD, keys);
      Script script = ScriptBuilder.createP2SHOutputScript(redeemScript);
      LegacyAddress legacyAddress = LegacyAddress.fromScriptHash(MAIN_NET, script.getPubKeyHash());

      // update multi sign account
      keys.forEach((i) -> multiSignAccount.addPublicKey(i.getPublicKeyAsHex()));
      multiSignAccount.setMultiSigAddress(legacyAddress.toBase58());
      log.info(multiSignAccount.toString());

      return multiSignAccount;
    }
    else
    {
      return null;
    }
  }

  public List<ECKey> generateECKeys(int size) {
    if (size > MAX_EC_KEY_SIZE) {
      return null;
    }
    else
    {
      List<ECKey> ecKeys = new ArrayList<>();
      for (int i = 0; i < size; ++i) {
        ecKeys.add(new ECKey());
      }
      return ecKeys;
    }
  }

  public static boolean isBTCValidAddress(String address) {
    try {
      LegacyAddress legacyAddress = LegacyAddress.fromBase58(MAIN_NET, address);
      if (legacyAddress != null) {
        return true;
      }
      else
      {
        return false;
      }
    } catch (Exception e) {
      return false;
    }
  }
}
