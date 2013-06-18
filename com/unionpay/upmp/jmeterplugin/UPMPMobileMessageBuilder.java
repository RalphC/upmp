package com.unionpay.upmp.jmeterplugin;

import java.security.GeneralSecurityException;
import java.util.Map;

import org.apache.jorphan.logging.LoggingManager;
import org.apache.log.Logger;

import com.unionpay.upmp.util.*;

public class UPMPMobileMessageBuilder {
	
	private static final Logger log = LoggingManager.getLoggerForClass();
	
	static String KEY_INITKEY = "initkey";
	static String KEY_PARAMS = "params";
	static String KEY_TN = "tn";
	static String KEY_SECRET = "secret";
	
	public static String BuildMessage(Map<String, String> req, String type) {
		RequestTemplate.init("RequestTemplate.conf");
		String Message = "";
		switch (type) {
		case "init" : Message = buildInit(req);
		}
		return Message;
	}
	
	private static String buildInit(Map<String, String> req){
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_INITKEY));
	
		Map<String,Object> initReq = RequestTemplate.getInitReqTemplate();
		Map<String, Object> initParams= (Map<String, Object>) initReq.get(KEY_PARAMS);
		
		initParams.put(KEY_TN, req.get(KEY_TN));
		initParams.put(KEY_SECRET, BytesUtil.bytesToHex(key));

		return encrypt(key, initReq);
	}
	
	
	private static String encrypt(byte[] key, Map<String,Object> req) {
		String request = JsonUtil.toJson(req).toString();
		log.info("request:" + request);
		byte[] hex = null;
		try {
			hex = DESUtil.ecbEncrypt(key, request.getBytes(), 2);
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return BytesUtil.bytesToHex(hex);
	}
	
}
