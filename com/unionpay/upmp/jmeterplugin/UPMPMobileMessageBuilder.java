package com.unionpay.upmp.jmeterplugin;

import java.util.HashMap;
import java.util.Map;

import com.unionpay.upmp.util.BytesUtil;
import com.unionpay.upmp.util.JsonUtil;
import com.unionpay.upmp.util.SecurityUtil;
import com.unionpay.upmp.util.UPMPConstant;

@SuppressWarnings("unchecked")
public class UPMPMobileMessageBuilder {
	
	public static  Map<String, Map<String,Object>> requestJson;
	
	static String KEY_INITKEY 			= "initkey";
	static String KEY_PARAMS 			= "params";
	static String KEY_SECRET 			= "secret";
	static String INIT 					= "init";
	
	static {
		requestJson = JsonUtil.fromFile(UPMPConstant.request_template, Map.class);
    }
    
	public static Map<String,Object> getReqTemplate(String TemplateName){
	    return mapClone(requestJson.get(TemplateName));
	}
	
	public static Map<String,Object> mapClone(Map<String,Object> req){
	    Map<String,Object> map = new HashMap<String, Object>();
        for (String key : req.keySet()) {
            Object value = req.get(key);
            if (KEY_PARAMS.equals(key)){
                Map<String,String> paramsMap = (Map<String,String>)value;
                Map<String,Object> params = new HashMap<String, Object>();
                for (String key1 : paramsMap.keySet()) {
                    Object value1 = paramsMap.get(key1);
                    params.put(key1, value1);
                }
                map.put(key, params);
            }else {
                map.put(key, value);
            }
        }
        return map;
	}
	
	public static String BuildMessage(Map<String, String> req, String type) {
		String Message = "";
		if (type.equals(INIT)) {
			Message = buildInit(req);
		} else {
			Message = buildMessage(req, type);
		}
		return Message;
	}

	private static String buildInit(Map<String, String> req){
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_INITKEY));
		req.remove(KEY_INITKEY);
		req.put(KEY_SECRET, BytesUtil.bytesToHex(key));
		
		Map<String,Object> initReq = getReqTemplate(INIT);
		Map<String, Object> initParams= (Map<String, Object>) initReq.get(KEY_PARAMS);
		initParams.putAll(req);
		
		return SecurityUtil.encrypt(key, initReq);
	}
		
	private static String buildMessage(Map<String, String> req, String messageType){
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
		req.remove(KEY_SECRET);
		
		Map<String,Object> messageReq = getReqTemplate(messageType);
		Map<String, Object> messageParams= (Map<String, Object>) messageReq.get(KEY_PARAMS);
		messageParams.putAll(req);
		
		return SecurityUtil.encrypt(key, messageReq);
	}
		
}
