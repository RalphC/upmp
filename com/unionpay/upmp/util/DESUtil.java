package com.unionpay.upmp.util;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class DESUtil
{
  public static final int EASY_PADDING = 2;
  public static final int PBOC_PADDING = 1;
  public static final int NO_PADDING = 0;

  public static byte[] genKey(String seed)
  {
    try
    {
      KeyGenerator kgen = KeyGenerator.getInstance("DESede");
      SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
      random.setSeed(seed.getBytes());
      kgen.init(112);
      SecretKey secretKey = kgen.generateKey();
      byte[] key = new byte[16];
      System.arraycopy(secretKey.getEncoded(), 0, key, 0, 16);
      return key;
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  private static byte[] internalCrypt(int enc, int ecb, byte[] key, byte[] data, byte[] iv, int padding) throws GeneralSecurityException
  {
    if ((key == null) || ((key.length != 8) && (key.length != 16) && (key.length != 24))) {
      throw new IllegalArgumentException();
    }
    if (data == null) {
      throw new IllegalArgumentException();
    }
    Cipher c = Cipher.getInstance(ecb != 0 ? "DESede/ECB/NoPadding" : "DESede/CBC/NoPadding");

    byte[] deskey = new byte[24];
    if (key.length == 8) {
      System.arraycopy(key, 0, deskey, 0, 8);
      System.arraycopy(key, 0, deskey, 8, 8);
      System.arraycopy(key, 0, deskey, 16, 8);
    } else if (key.length == 16) {
      System.arraycopy(key, 0, deskey, 0, 16);
      System.arraycopy(key, 0, deskey, 16, 8);
    } else {
      System.arraycopy(key, 0, deskey, 0, 24);
    }

    byte[] desdata = data;
    if (padding == 1) {
      desdata = new byte[(data.length / 8 + 1) * 8];
      System.arraycopy(data, 0, desdata, 0, data.length);
      desdata[data.length] = -128;
      Arrays.fill(desdata, data.length + 1, desdata.length, (byte)0);
    } else if ((padding == 2) && 
      (data.length % 8 != 0)) {
      desdata = new byte[(data.length / 8 + 1) * 8];
      System.arraycopy(data, 0, desdata, 0, data.length);
      Arrays.fill(desdata, data.length, desdata.length, (byte)0);
    }

    if (ecb != 0) {
      c.init(enc != 0 ? 1 : 2, new SecretKeySpec(deskey, "DESede"));
    } else {
      byte[] zero = { 0, 0, 0, 0, 0, 0, 0, 0 };
      if (iv == null)
        iv = zero;
      IvParameterSpec ivps = new IvParameterSpec(iv);
      c.init(enc != 0 ? 1 : 2, new SecretKeySpec(deskey, "DESede"), ivps);
    }

    return c.doFinal(desdata);
  }

  public static byte[] ecbEncrypt(byte[] key, byte[] data, int padding)
    throws GeneralSecurityException
  {
    return internalCrypt(1, 1, key, data, null, padding);
  }

  public static byte[] ecbDecrypt(byte[] key, byte[] data, int padding) throws GeneralSecurityException
  {
    return internalCrypt(0, 1, key, data, null, padding);
  }

  public static byte[] cbcEncrypt(byte[] key, byte[] data, int padding) throws GeneralSecurityException
  {
    return internalCrypt(1, 0, key, data, null, padding);
  }

  public static byte[] cbcEncrypt(byte[] key, byte[] data, byte[] iv, int padding) throws GeneralSecurityException
  {
    return internalCrypt(1, 0, key, data, iv, padding);
  }

  public static byte[] cbcDecrypt(byte[] key, byte[] data, int padding) throws GeneralSecurityException
  {
    return internalCrypt(0, 0, key, data, null, padding);
  }

  public static byte[] cbcDecrypt(byte[] key, byte[] data, byte[] iv, int padding) throws GeneralSecurityException
  {
    return internalCrypt(0, 0, key, data, iv, padding);
  }

  public static byte[] generateKey(int keylen, int bytelen) throws GeneralSecurityException
  {
    if ((keylen != 8) && (keylen != 16) && (keylen != 24)) {
      throw new IllegalArgumentException();
    }
    if ((bytelen != 8) && (bytelen != 16) && (bytelen != 24)) {
      throw new IllegalArgumentException();
    }
    if (keylen > bytelen) {
      throw new IllegalArgumentException();
    }
    KeyGenerator kg = KeyGenerator.getInstance("DESede");
    byte[] key = kg.generateKey().getEncoded();

    byte[] bytes = new byte[bytelen];
    if (keylen == 8) {
      System.arraycopy(key, 0, bytes, 0, 8);
      if (bytelen >= 16)
        System.arraycopy(key, 0, bytes, 8, 8);
      if (bytelen == 24)
        System.arraycopy(key, 0, bytes, 16, 8);
    } else if (keylen == 16) {
      System.arraycopy(key, 0, bytes, 0, 16);
      if (bytelen == 24)
        System.arraycopy(key, 0, bytes, 16, 8);
    } else {
      System.arraycopy(key, 0, bytes, 0, 24);
    }

    return bytes;
  }

  public static byte[] computeMac(byte[] key, byte[] mab, byte[] iv, int padding) throws GeneralSecurityException
  {
    if ((key == null) || (mab == null) || (iv == null)) {
      throw new IllegalArgumentException();
    }
    
    if ((key.length != 8) && (key.length != 16) && (key.length != 24)) {
      throw new IllegalArgumentException();
    }
    
    if ((padding < 0) || (padding > 2)) {
      throw new IllegalArgumentException();
    }
    
    byte[] data;
    if (padding == 1) {
      int datalen = (mab.length / 8 + 1) * 8;
      data = new byte[datalen];
      System.arraycopy(mab, 0, data, 0, mab.length);
      data[mab.length] = -128;
      for (int i = data.length + 1; i < data.length; i++)
        data[i] = 0;
    } else if (padding == 2)
    {
      if (mab.length % 8 == 0) {
        int datalen = mab.length;
        data = new byte[datalen];
        data = mab;
      } else {
        int datalen = (mab.length / 8 + 1) * 8;
        data = new byte[datalen];
        System.arraycopy(mab, 0, data, 0, mab.length);
        for (int i = data.length; i < data.length; i++)
          data[i] = 0;
      }
    } else {
      int datalen = mab.length;
      data = new byte[datalen];
      data = mab;
    }

    byte[] block = new byte[8];
    for (int i = 0; i < data.length / 8; i++) {
      System.arraycopy(data, i * 8, block, 0, 8);
      for (int j = 0; j < 8; j++)
      {
        int tmp271_269 = j;
        byte[] tmp271_267 = block; tmp271_267[tmp271_269] = ((byte)(tmp271_267[tmp271_269] ^ iv[j]));
      }
      iv = ecbEncrypt(key, block, 0);
    }

    return iv;
  }

  public static byte[] computeMac(byte[] key, byte[] mab, int padding) throws GeneralSecurityException
  {
    byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0 };
    return computeMac(key, mab, iv, padding);
  }

  public static byte[] diversify(byte[] key, byte[] factor) throws GeneralSecurityException
  {
    if ((key == null) || (factor == null)) {
      throw new IllegalArgumentException();
    }
    if ((key.length != 8) && (key.length != 16) && (key.length != 24)) {
      throw new IllegalArgumentException();
    }
    if (factor.length != 8) {
      throw new IllegalArgumentException();
    }
    byte[] result = new byte[16];
    byte[] tmp = ecbEncrypt(key, factor, 0);
    System.arraycopy(tmp, 0, result, 0, 8);

    for (int i = 0; i < 8; i++)
      factor[i] = ((byte)(factor[i] ^ 0xFFFFFFFF));
    tmp = ecbEncrypt(key, factor, 0);
    System.arraycopy(tmp, 0, result, 8, 8);
    return result;
  }
}