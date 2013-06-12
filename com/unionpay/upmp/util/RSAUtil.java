package com.unionpay.upmp.util;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

public class RSAUtil {
	  public static final String RSA = "RSA";
	  public static final String RSA_PADDING_MODE = "RSA";
	  public static final String ALGORITHM_RSA_SIGN = "SHA1withRSA";
	  public static final int RSAKEYLEN = 2048;
	  //private static final String RSAPUBKEYFILE = "rsaPublicKey";
	  //private static final String RSAPRIKEYFILE = "rsaPrivateKey";
	  public static final String modulus = "18044025098287483444264561990325279620342511820853300370434639555504041207259084955525340604787949303816554427474696038570689317337164666792743231985627426027861552272885998365747333516335809597569460967823961065252540017041042370560314283732494048259273337583526461691981187322825623057255658372853898830208258113197828164724771529638970340431105881411391265845023709046099299321896533858208814913475816777522627812575117409909952283194561859472093728228073457266627392329836048064434005160589573112391922824946632661816183616674395499578861305937778467769133707422261556852995652065073875504843470144498263472174033";
	  public static final String publicExponent = "65537";

	  public static byte[] encrypt(byte[] data, PublicKey publicKey)
	  {
	    try
	    {
	      Cipher cipher = Cipher.getInstance("RSA");
	      cipher.init(1, publicKey);
	      return cipher.doFinal(data);
	    } catch (Exception e) {
	      throw new RuntimeException(e);
	    }
	  }

	  public static byte[] decrypt(byte[] data, PrivateKey privateKey)
	  {
	    try
	    {
	      Cipher cipher = Cipher.getInstance("RSA");
	      cipher.init(2, privateKey);
	      return cipher.doFinal(data);
	    } catch (Exception e) {
	      throw new RuntimeException(e);
	    }
	  }

	  public static byte[] sign(PrivateKey key, byte[] tbsData)
	    throws Exception
	  {
	    Signature sig = Signature.getInstance("SHA1withRSA");
	    sig.initSign(key);
	    sig.update(tbsData);
	    return sig.sign();
	  }

	  public static boolean verify(PublicKey key, byte[] message, byte[] signature)
	    throws Exception
	  {
	    Signature sig = Signature.getInstance("SHA1withRSA");
	    sig.initVerify(key);
	    sig.update(message);
	    return sig.verify(signature);
	  }

	  public static KeyPair genRSAKeyPair()
	  {
	    return genRSAKeyPair(2048);
	  }

	  public static KeyPair genRSAKeyPair(int keyLength)
	  {
	    try
	    {
	      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	      keyPairGenerator.initialize(keyLength);
	      return keyPairGenerator.generateKeyPair();
	    } catch (Exception e) {
	      throw new RuntimeException(e);
	    }
	  }

	  public static void genRSAKeyPairAndSaveToFile()
	  {
	    genRSAKeyPairAndSaveToFile(2048, "");
	  }

	  public static void genRSAKeyPairAndSaveToFile(String dir) {
	    genRSAKeyPairAndSaveToFile(2048, dir);
	  }

	  public static void genRSAKeyPairAndSaveToFile(int keyLength, String dir)
	  {
	    KeyPair keyPair = genRSAKeyPair(keyLength);

	    PublicKey publicKey = keyPair.getPublic();
	    PrivateKey privateKey = keyPair.getPrivate();

	    DataOutputStream dos = null;
	    try {
	      dos = new DataOutputStream(new FileOutputStream(dir + "rsaPublicKey"));
	      dos.write(publicKey.getEncoded());
	      dos.flush();
	    } catch (Exception e) {
	      throw new RuntimeException(e);
	    } finally {
	      if (dos != null) {
	        try {
	          dos.close();
	        } catch (IOException e) {
	          e.printStackTrace();
	        }
	      }

	    }

	    try
	    {
	      dos = new DataOutputStream(new FileOutputStream(dir + "rsaPrivateKey"));
	      dos.write(privateKey.getEncoded());
	      dos.flush();
	    } catch (Exception e) {
	      throw new RuntimeException(e);
	    } finally {
	      if (dos != null)
	        try {
	          dos.close();
	        } catch (IOException e) {
	          e.printStackTrace();
	        }
	    }
	  }

	  public static PrivateKey getPrivateKeyFromFile()
	  {
	    return getPrivateKeyFromFile(RSAUtil.class.getResourceAsStream("rsaPrivateKey"));
	  }

	  public static PrivateKey getPrivateKeyFromFile(String dir)
	  {
	    return getPrivateKeyFromFile(new File(dir + "rsaPrivateKey"));
	  }

	  public static PrivateKey getPrivateKeyFromFile(File keyFile)
	  {
	    try
	    {
	      return getPrivateKeyFromFile(new FileInputStream(keyFile));
	    } catch (FileNotFoundException e) {
	      throw new RuntimeException(e);
	    }
	  }

	  public static PrivateKey getPrivateKeyFromFile(InputStream is)
	  {
	    PrivateKey priKey = null;
	    try
	    {
	      BufferedInputStream bis = new BufferedInputStream(is);
	      ByteArrayOutputStream out = new ByteArrayOutputStream(2048);

	      byte[] temp = new byte[2048];
	      int size = 0;
	      while ((size = bis.read(temp)) != -1) {
	        out.write(temp, 0, size);
	      }
	      byte[] privatekey = out.toByteArray();
	      PKCS8EncodedKeySpec pkcs8keyspec = new PKCS8EncodedKeySpec(privatekey);
	      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	      priKey = keyFactory.generatePrivate(pkcs8keyspec);
	    }
	    catch (Exception e) {
	      throw new RuntimeException(e);
	    } finally {
	      if (is != null) {
	        try {
	          is.close();
	        } catch (IOException e) {
	          e.printStackTrace();
	        }
	      }
	    }
	    return priKey;
	  }

	  public static RSAPublicKeySpec getPublicKeyFromFile()
	  {
	    return getPublicKeyFromFile(RSAUtil.class.getResourceAsStream("rsaPublicKey"));
	  }

	  public static RSAPublicKeySpec getPublicKeyFromFile(InputStream is)
	  {
	    RSAPublicKeySpec pubKeySpec = null;
	    BufferedInputStream bis = null;
	    try
	    {
	      bis = new BufferedInputStream(is);
	      ByteArrayOutputStream out = new ByteArrayOutputStream(2048);

	      byte[] temp = new byte[2048];
	      int size = 0;
	      while ((size = bis.read(temp)) != -1) {
	        out.write(temp, 0, size);
	      }
	      byte[] publickey = out.toByteArray();
	      X509EncodedKeySpec bobPubKeySpec = new X509EncodedKeySpec(publickey);
	      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	      PublicKey pubKey = keyFactory.generatePublic(bobPubKeySpec);
	      pubKeySpec = (RSAPublicKeySpec)keyFactory.getKeySpec(pubKey, RSAPublicKeySpec.class);
	      System.out.println("modulus:" + pubKeySpec.getModulus());
	      System.out.println("publicExponent:" + pubKeySpec.getPublicExponent());
	    }
	    catch (Exception e)
	    {
	      throw new RuntimeException(e);
	    } finally {
	      if (bis != null) {
	        try {
	          bis.close();
	        } catch (IOException e) {
	          e.printStackTrace();
	        }
	      }
	    }
	    return pubKeySpec;
	  }

	  public static RSAPublicKeySpec getPublicKeyFromFile(String dir)
	  {
	    RSAPublicKeySpec pubKeySpec = null;
	    BufferedInputStream bis = null;
	    try
	    {
	      FileInputStream fis = new FileInputStream(dir + "rsaPublicKey");
	      bis = new BufferedInputStream(fis);

	      ByteArrayOutputStream out = new ByteArrayOutputStream(2048);

	      byte[] temp = new byte[2048];
	      int size = 0;
	      while ((size = bis.read(temp)) != -1) {
	        out.write(temp, 0, size);
	      }
	      fis.close();

	      byte[] publickey = out.toByteArray();
	      X509EncodedKeySpec bobPubKeySpec = new X509EncodedKeySpec(publickey);
	      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	      PublicKey pubKey = keyFactory.generatePublic(bobPubKeySpec);
	      pubKeySpec = (RSAPublicKeySpec)keyFactory.getKeySpec(pubKey, RSAPublicKeySpec.class);
	    } catch (Exception e) {
	      throw new RuntimeException(e);
	    } finally {
	      if (bis != null) {
	        try {
	          bis.close();
	        } catch (IOException e) {
	          e.printStackTrace();
	        }
	      }
	    }
	    return pubKeySpec;
	  }

	  public static PublicKey getPubKeyBySpec(RSAPublicKeySpec spec)
	  {
	    try
	    {
	      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	      return keyFactory.generatePublic(spec);
	    } catch (NoSuchAlgorithmException e) {
	      throw new RuntimeException(e);
	    } catch (InvalidKeySpecException e) {
	      throw new RuntimeException(e);
	    }
	  }

	  public static PublicKey generateRSAPublicKey(String modulus, String publicExponent)
	  {
	    try
	    {
	      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	      RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(publicExponent));
	      return keyFactory.generatePublic(pubKeySpec);
	    } catch (Exception e) {
	      throw new RuntimeException(e);
	    }
	  }

	  public static PublicKey generateRSAPublicKey(byte[] key)
	  {
	    try
	    {
	      X509EncodedKeySpec bobPubKeySpec = new X509EncodedKeySpec(key);
	      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	      return keyFactory.generatePublic(bobPubKeySpec);
	    }
	    catch (Exception e) {
	      throw new RuntimeException(e);
	    }
	  }

	  public static PrivateKey generateRSAPrivateKey(byte[] key)
	  {
	    try
	    {
	      PKCS8EncodedKeySpec pkcs8keyspec = new PKCS8EncodedKeySpec(key);
	      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	      return keyFactory.generatePrivate(pkcs8keyspec);
	    }
	    catch (Exception e) {
	      throw new RuntimeException(e);
	    }
	  }

	  public static void main(String[] args) throws Exception
	  {
	    getPublicKeyFromFile();
	  }
	
}
