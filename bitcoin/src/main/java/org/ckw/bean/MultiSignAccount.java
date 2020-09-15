package org.ckw.bean;

import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

@Data
@ToString
public class MultiSignAccount {
  String multiSigAddress;
  List<String> publicKeys = new ArrayList<>();

  public void addPublicKey(String key) {
    publicKeys.add(key);
  }
}
