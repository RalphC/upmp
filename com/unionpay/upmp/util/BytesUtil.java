package com.unionpay.upmp.util;

import org.apache.commons.codec.binary.Base64;

public class BytesUtil
{
  public static String base64Encode(byte[] bstr)
  {
    return Base64.encodeBase64String(bstr);
  }

  public static byte[] base64Decode(String str)
  {
    return Base64.decodeBase64(str);
  }

  public static byte[] hexToBytes(String hex)
  {
    return hexToBytes(hex.toCharArray());
  }

  public static byte[] hexToBytes(char[] hex)
  {
    int length = hex.length / 2;
    byte[] raw = new byte[length];
    for (int i = 0; i < length; i++) {
      int high = Character.digit(hex[(i * 2)], 16);
      int low = Character.digit(hex[(i * 2 + 1)], 16);
      int value = high << 4 | low;
      if (value > 127)
        value -= 256;
      raw[i] = ((byte)value);
    }
    return raw;
  }

  public static String bytesToHex(byte[] bytes)
  {
    String hexArray = "0123456789abcdef";
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      int bi = b & 0xFF;
      sb.append(hexArray.charAt(bi >> 4));
      sb.append(hexArray.charAt(bi & 0xF));
    }
    return sb.toString();
  }
}
