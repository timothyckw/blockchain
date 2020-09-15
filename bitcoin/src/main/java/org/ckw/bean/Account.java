package org.ckw.bean;

import lombok.Data;
import lombok.ToString;

import java.util.List;

@Data
@ToString
public class Account {
  String publicKey;
  String privateKey;
  String segWitAddress;
  String legacyAddress;
  List<String> mnemonicCode;
}
