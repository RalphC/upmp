package com.unionpay.upmp.jmeterplugin;

import java.security.GeneralSecurityException;
import java.util.Map;

import org.apache.jorphan.logging.LoggingManager;
import org.apache.log.Logger;

import com.unionpay.upmp.util.*;

public class UPMPMobileMessageBuilder {
	
	private static final Logger log = LoggingManager.getLoggerForClass();
	
	static String KEY_INITKEY 			= "initkey";
	static String KEY_PARAMS 			= "params";
	static String KEY_TN 				= "tn";
	static String KEY_SECRET 			= "secret";
	static String KEY_USER 				= "user";
	static String KEY_LOCAL 			= "local";
	static String KEY_TERMINAL_TYPE 	= "terminal_type";
	static String KEY_TERMINAL_VERSION 	= "terminal_version";
	static String KEY_OS_NAME 			= "os_name";
	static String KEY_OS_VERSION 		= "os_version";
	static String KEY_CARD_TYPE 		= "card_tp";
	static String KEY_BANK 				= "bank";
	static String KEY_PAN 				= "pan";
	static String KEY_MOBILE 			= "mobile";
	
	
	public static String BuildMessage(Map<String, String> req, String type) {
		RequestTemplate.init("RequestTemplate.conf");
		String Message = "";
		switch (type) {
		case RequestTemplate.INIT 		: Message = buildInit(req);
		case RequestTemplate.RULES 		: Message = buildRules(req);
		case RequestTemplate.RULES2P1 	: Message = buildRules2p1(req);
		case RequestTemplate.SMS 		: Message = buildSMS(req);
		case RequestTemplate.UNBINDCARD : Message = buildUnbind(req);
		case RequestTemplate.ENTRUST	: Message = buildEntrust(req);
		case RequestTemplate.VERIFY		: Message = buildVerify(req);
		}
		return Message;
	}

	private static String buildInit(Map<String, String> req){
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_INITKEY));
		req.remove(KEY_INITKEY);
		req.put(KEY_SECRET, BytesUtil.bytesToHex(key));
		
		Map<String,Object> initReq = RequestTemplate.getInitReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> initParams= (Map<String, Object>) initReq.get(KEY_PARAMS);
		
		initParams.putAll(req);
		return encrypt(key, initReq);
	}
		
	private static String buildRules(Map<String, String> req){
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
	
		Map<String,Object> initReq = RequestTemplate.getRulesReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> initParams= (Map<String, Object>) initReq.get(KEY_PARAMS);
		
		addValue(req, initParams, KEY_CARD_TYPE);
		addValue(req, initParams, KEY_BANK);
		
		return encrypt(key, initReq);
	}
	
	private static String buildRules2p1(Map<String, String> req){
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
	
		Map<String,Object> initReq = RequestTemplate.getRules2p1ReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> initParams= (Map<String, Object>) initReq.get(KEY_PARAMS);
		
		initParams.put(KEY_PAN, req.get(KEY_PAN));
		
		return encrypt(key, initReq);
	}
	
	private static String buildSMS(Map<String, String> req){
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
	
		Map<String,Object> initReq = RequestTemplate.getSmsReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> initParams= (Map<String, Object>) initReq.get(KEY_PARAMS);
		
		initParams.put(KEY_TN, req.get(KEY_TN));
		initParams.put(KEY_MOBILE, req.get(KEY_MOBILE));
		initReq.put(KEY_PAN, req.get(KEY_PAN));
		
		return encrypt(key, initReq);
	}
	
	private static String buildUnbind(Map<String, String> req){
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
	
		Map<String,Object> initReq = RequestTemplate.getUnbindCardReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> initParams= (Map<String, Object>) initReq.get(KEY_PARAMS);
		
		initParams.put(KEY_PAN, req.get(KEY_PAN));
		
		return encrypt(key, initReq);
	}
	
	private static String buildEntrust(Map<String, String> req){
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
		
		Map<String,Object> initReq = RequestTemplate.getEntrustReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> initParams= (Map<String, Object>) initReq.get(KEY_PARAMS);
		
		req.remove(KEY_SECRET);
		initParams.putAll(req);
		
		return encrypt(key, initReq);
	}
	
	private static String buildVerify(Map<String, String> req){
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
		
		Map<String,Object> initReq = RequestTemplate.getVerifyReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> initParams= (Map<String, Object>) initReq.get(KEY_PARAMS);
		
		initParams.putAll(req);	
		return encrypt(key, initReq);
	}
	
	private static String buildPay(Map<String, String> req) {
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
		
		Map<String,Object> payReq = RequestTemplate.getPayReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> initParams= (Map<String, Object>) payReq.get(KEY_PARAMS);
		
		initParams.putAll(req);	
		return encrypt(key, payReq);
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
	
	private static void addValue(Map<?, ?> src, Map<String, Object> dst, String key) {
		if (src.containsKey(key)) dst.put(key, src.get(key));
	}
	
}
