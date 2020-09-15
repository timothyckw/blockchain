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
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;

import static org.bitcoinj.crypto.HDUtils.*;

@Slf4j
@RestController
public class AddressGenerator {

  private static final MainNetParams MAIN_NET = MainNetParams.get();
  private static final TestNet3Params TEST_NET = TestNet3Params.get();

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
    Account account = new Account();

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
    MultiSignAccount multiSignAccount = new MultiSignAccount();

    // generate random ECKey
    ECKey ecKey1 = new ECKey();
    ECKey ecKey2 = new ECKey();
    ECKey ecKey3 = new ECKey();

    // create a 2-of-3 multi sign redeemScript (output script)
    List<ECKey> keys = Arrays.asList(ecKey1, ecKey2, ecKey3);

    // create scrip for generate legacy address
    Script redeemScript = ScriptBuilder.createRedeemScript(2, keys);
    Script script = ScriptBuilder.createP2SHOutputScript(redeemScript);
    LegacyAddress legacyAddress = LegacyAddress.fromScriptHash(MAIN_NET, script.getPubKeyHash());

    // update multi sign account
    keys.forEach((i) -> multiSignAccount.addPublicKey(i.getPublicKeyAsHex()));
    multiSignAccount.setMultiSigAddress(legacyAddress.toBase58());
    log.info(multiSignAccount.toString());

    return multiSignAccount;
  }

  public static boolean isBTCValidAddress(String address) {
    try {
      LegacyAddress legacyAddress = LegacyAddress.fromBase58(MAIN_NET, address);
      if (legacyAddress != null) {
        return true;
      } else {
        return false;
      }
    } catch (Exception e) {
      return false;
    }
  }
}
