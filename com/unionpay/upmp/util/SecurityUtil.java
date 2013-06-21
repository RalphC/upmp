package com.unionpay.upmp.util;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.jorphan.logging.LoggingManager;
import org.apache.log.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.unionpay.upmp.sdk.conf.UpmpConfig;
import com.unionpay.upmp.sdk.util.UpmpCore;

public class SecurityUtil {
	private static final Logger logger = LoggingManager.getLoggerForClass();
	public static final String QSTRING_EQUAL = "=";
	public static final String QSTRING_SPLIT = "&";
	private static X509Certificate encryptCert = null;

	public static void initEncryptCert()
	{
		CertificateFactory cf = null;
		FileInputStream in = null;
		try {
			cf = CertificateFactory.getInstance("X.509");
			in = new FileInputStream(UPMPConstant.encryptCertPath);
			encryptCert = (X509Certificate)cf.generateCertificate(in);
		}
		catch (CertificateException e)
		{
			logger.error(e.getMessage());
		}
		catch (FileNotFoundException e)
		{
			logger.error(e.getMessage());
		}
		finally
		{
			if (null != in)
				try {
					in.close();
				}
			catch (IOException e)
			{
				logger.error(e.getMessage());
			}
		}
	}

	private static String md5(String str, String charset)
	{
		if (str == null) {
			return null;
		}

		MessageDigest messageDigest = null;
		try
		{
			messageDigest = MessageDigest.getInstance("MD5");
			messageDigest.reset();
			messageDigest.update(str.getBytes(charset));
		} catch (NoSuchAlgorithmException e) {
			return str;
		} catch (UnsupportedEncodingException e) {
			return str;
		}

		byte[] byteArray = messageDigest.digest();

		StringBuffer md5StrBuff = new StringBuffer();

		for (int i = 0; i < byteArray.length; i++) {
			if (Integer.toHexString(0xFF & byteArray[i]).length() == 1) {
				md5StrBuff.append("0").append(Integer.toHexString(0xFF & byteArray[i]));
			}
			else {
				md5StrBuff.append(Integer.toHexString(0xFF & byteArray[i]));
			}
		}
		return md5StrBuff.toString();
	}

	public static String generateSignature(String qstring, String securityKey, String charset)
	{
		if (null == qstring) {
			return null;
		}
		return md5(qstring + md5(securityKey, charset), charset);
	}

	public static boolean checkSign(String qstring, String signature, String securityKey, String charset)
	{
		logger.debug("Request signature: " + signature);
		if (null == signature) {
			return false;
		}
		String generateSignature = md5(qstring + md5(securityKey, charset), charset);
		logger.debug("request to be signatured: " + qstring);
		logger.debug("Generate signature: " + generateSignature);
		return signature.equals(generateSignature);
	}

	public static boolean checkSign(Map<String, String> req, String securityKey)
	{
		String signature = (String)req.get("signature");
		logger.debug("Request signature: " + signature);
		if (null == signature) {
			return false;
		}

		Map<String, String> filterReq = paraRailwayFilter(req);
		String generateSignature = buildSignature(filterReq, securityKey);
		logger.debug("Generate signature: " + generateSignature);
		return signature.equals(generateSignature);
	}

	public static String buildSignature(Map<String, String> req, String securityKey)
	{
		String charset = (String)req.get("charset");
		String prestr = createLinkString(charset, req, true, false);
		prestr = prestr + "&" + md5(securityKey, charset);
		return md5(prestr, charset);
	}

	public static String createLinkString(String charset, Map<String, String> para, boolean sort, boolean encode)
	{
		List<String> keys = new ArrayList<String>(para.keySet());

		if (sort) {
			Collections.sort(keys);
		}
		if (StringUtils.isEmpty(charset)) {
			charset = "utf-8";
		}

		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < keys.size(); i++) {
			String key = (String)keys.get(i);
			String value = (String)para.get(key);
			if (encode)
				try {
					value = URLEncoder.encode(value, charset);
				}
				catch (UnsupportedEncodingException e) {
				}
			if (i == keys.size() - 1)
				sb.append(key).append("=").append(value);
			else {
				sb.append(key).append("=").append(value).append("&");
			}
		}
		return sb.toString();
	}

	public static Map<String, String> paraFilter(Map<String, String> para)
	{
		Map<String, String> result = new HashMap<String, String>();

		if ((para == null) || (para.size() <= 0)) {
			return result;
		}

		for (String key : para.keySet()) {
			String value = (String)para.get(key);
			if ((!StringUtils.isEmpty(value)) && (!key.equalsIgnoreCase("signature")) && (!key.equalsIgnoreCase("signMethod")))
			{
				result.put(key, value);
			}
		}
		return result;
	}

	public static Map<String, String> paraRailwayFilter(Map<String, String> para)
	{
		Map<String, String> result = new HashMap<String, String>();

		if ((para == null) || (para.size() <= 0)) {
			return result;
		}

		for (String key : para.keySet()) {
			String value = (String)para.get(key);
			if ((!key.equalsIgnoreCase("signature")) && (!key.equalsIgnoreCase("signMethod")))
			{
				result.put(key, value);
			}
		}
		return result;
	}

	public static boolean checkRailwaySign(Map<String, String> req, String securityKey)
	{
		String signature = (String)req.get("signature");
		logger.debug("Request signature: " + signature);
		if (null == signature) {
			return false;
		}
		Map<String, String> filterReq = paraRailwayFilter(req);
		String generateSignature = buildSignature(filterReq, securityKey);
		return signature.equals(generateSignature);
	}

	public static boolean verifyRailwayResponse(String respString, Map<String, String> resp)
	{
		boolean signIsValid = false;
		if ((respString != null) && (!"".equals(respString)))
		{
			Map<String, String> para;
			try {
				para = UpmpCore.parseQString(respString);
			} catch (Exception e) {
				logger.error(e.getMessage());
				return signIsValid;
			}

			String respSignature = (String)para.get("signature");

			Map<String, String> filteredReq = paraRailwayFilter(para);
			String signature = buildSignature(filteredReq, UpmpConfig.SECURITY_KEY);

			if ((null != respSignature) && (respSignature.equals(signature))) signIsValid = true;
			resp.putAll(para);

			return signIsValid;
		}

		return signIsValid;
	}

	public static PublicKey getEncryptCertPublicKey()
	{
		try
		{
			if (null == encryptCert) initEncryptCert();
			return encryptCert.getPublicKey(); 
		} catch (Exception e) {
			logger.error(e.getMessage());
		}
		return null;
	}

	public static String encryptCvn2(String cvn2, String encoding)
	{
		return encryptData(cvn2, encoding, getEncryptCertPublicKey());
	}

	public static String encryptExpire(String expire, String encoding)
	{
		return encryptData(expire, encoding, getEncryptCertPublicKey());
	}

	public static String encryptData(String data, String encoding, PublicKey key)
	{
		try	{
			byte[] encryptedData = encryptDataBytes(key, data.getBytes(encoding));
			return new String(base64Encode(encryptedData), encoding); 
		} catch (Exception e) {
			logger.error(e.getMessage());
		}
		return "";
	}

	public static String encryptPin(String pin, String pan, String encoding)
	{
		byte[] pinBlock = pin2PinBlockWithPan(pin, pan);
		try	{
			byte[] result = encryptDataBytes(getEncryptCertPublicKey(), pinBlock);
			return new String(base64Encode(result), encoding);
		} catch (Exception e) {
			logger.error(e.getMessage());
		}
		return "";
	}

	public static byte[] pin2PinBlockWithPan(String pin, String pan)
	{
		byte[] pinBytes = pin2PinBlock(pin);
		if (pan.length() == 11)
			pan = "00" + pan;
		else if (pan.length() == 12) {
			pan = "0" + pan;
		}
		byte[] panBytes = formatPan(pan);
		byte[] result = new byte[8];
		for (int i = 0; i < 8; i++) {
			result[i] = ((byte)(pinBytes[i] ^ panBytes[i]));
		}
		return result;
	}

	public static byte[] pin2PinBlock(String pin)
	{
		int temp = 1;
		int pinLength = pin.length();

		byte[] result = new byte[8];
		try {
			result[0] = ((byte)Integer.parseInt(new Integer(pinLength).toString(), 10));
			if (pinLength % 2 == 0)
				for (int i = 0; i < pinLength; ) {
					String subPin = pin.substring(i, i + 2);
					result[temp] = ((byte)Integer.parseInt(subPin, 16));
					if ((i == pinLength - 2) && 
							(temp < 7)) {
						for (int x = temp + 1; x < 8; x++) {
							result[x] = -1;
						}
					}

					temp++;
					i += 2;
				}
			else
				for (int i = 0; i < pinLength - 1; ) {
					String subPin = pin.substring(i, i + 2);
					result[temp] = ((byte)Integer.parseInt(subPin, 16));
					if (i == pinLength - 3) {
						subPin = pin.substring(pinLength - 1) + "F";
						result[(temp + 1)] = ((byte)Integer.parseInt(subPin, 16));
						if (temp + 1 < 7) {
							for (int x = temp + 2; x < 8; x++) {
								result[x] = -1;
							}
						}
					}
					temp++;
					i += 2;
				}
		}
		catch (Exception e)
		{
			logger.error(e.getMessage());
		}
		return result;
	}

	public static byte[] formatPan(String pan)
	{
		int panLength = pan.length();
		byte[] result = new byte[8];
		int temp = panLength - 13;
		try {
			result[0] = 0;
			result[1] = 0;
			for (int i = 2; i < 8; i++) {
				String subPan = pan.substring(temp, temp + 2);
				result[i] = ((byte)Integer.parseInt(subPan, 16));
				temp += 2;
			}
		} catch (Exception e) {
		}
		return result;
	}

	public static byte[] base64Encode(byte[] inputByte)	throws IOException
	{
		return Base64.encodeBase64(inputByte);
	}

	public static byte[] encryptDataBytes(PublicKey publicKey, byte[] data)	{
		try	{
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", new BouncyCastleProvider());

			cipher.init(1, publicKey);
			int blockSize = cipher.getBlockSize();
			int outputSize = cipher.getOutputSize(data.length);
			int leavedSize = data.length % blockSize;
			int blocksSize = leavedSize != 0 ? data.length / blockSize + 1 : data.length / blockSize;

			byte[] raw = new byte[outputSize * blocksSize];
			int i = 0;
			while (data.length - i * blockSize > 0) {
				if (data.length - i * blockSize > blockSize)
					cipher.doFinal(data, i * blockSize, blockSize, raw, i * outputSize);
				else {
					cipher.doFinal(data, i * blockSize, data.length - i * blockSize, raw, i * outputSize);
				}

				i++;
			}
			return raw;
		} catch (Exception e) {
			logger.error(e.getMessage());
			return null;
		}
	}

	static
	{
		initEncryptCert();
	}
}
