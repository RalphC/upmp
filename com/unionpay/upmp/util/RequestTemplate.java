package com.unionpay.upmp.util;

import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("unchecked")
public class RequestTemplate {
	public static  Map<String, Map<String,Object>> requestJson;
	
	public static final String INIT = "init";
	public static final String RULES = "rules";
	public static final String SMS = "sms";
	public static final String UNBINDCARD = "unbind";
	public static final String VERIFY = "verify";
	public static final String PAY = "pay";
	public static final String QUERY = "query";
	public static final String BANKS = "banks";
	public static final String MOREBANKS = "morebanks";
	public static final String RULES2P1 = "rules2p1";
	public static final String ENTRUST = "entrust";
	public static final String ENTRUSTNEW = "entrustnew";
	public static final String RULESNEW = "rulesnew";
	public static final String VERIFYNEW = "verifynew";
	public static final String FOLLOWRULES = "followrules";
	public static final String OPENRULES = "openrules";
	public static final String OPENUPGRADE = "openupgrade";
	public static final String PAYNEW = "paynew";
	public static final String QUERYNEW = "querynew";
	public static final String SMSNEW = "smsnew";
	public static final String UNBINDCARDNEW = "unbindnew";
    
    public static void init(String file) {
    	requestJson = JsonUtil.fromFile(file, Map.class);
    }
	
	public static Map<String,Object> getInitReqTemplate(){
	    return mapClone(requestJson.get(INIT));
	}
	
	public static Map<String,Object> getRulesReqTemplate(){
	    return mapClone(requestJson.get(RULES));
	}
	
    public static Map<String, Object> getSmsReqTemplate() {
        return mapClone(requestJson.get(SMS));
    }
    
    public static Map<String, Object> getUnbindCardReqTemplate() {
        return mapClone(requestJson.get(UNBINDCARD));
    }
	
	public static Map<String,Object> getVerifyReqTemplate(){
		return mapClone(requestJson.get(VERIFY));
	}
	
	public static Map<String,Object> getPayReqTemplate(){
		return mapClone(requestJson.get(PAY));
	}
	
	public static Map<String,Object> getQueryReqTemplate(){
		return mapClone(requestJson.get(QUERY));
	}
	
	public static Map<String,Object> getBanksReqTemplate(){
		return mapClone(requestJson.get(BANKS));
	} 
	
	public static Map<String,Object> getMoreBanksReqTemplate(){
		return mapClone(requestJson.get(MOREBANKS));
	} 
	
    public static Map<String, Object> getRules2p1ReqTemplate() {
        return mapClone(requestJson.get(RULES2P1));
    }
    
    public static Map<String, Object> getEntrustReqTemplate() {
        return mapClone(requestJson.get(ENTRUST));
    }
	
    public static Map<String, Object> getEntrustNewReqTemplate() {
    	return mapClone(requestJson.get(ENTRUSTNEW));
    }

    public static Map<String, Object> getRulesNewReqTemplate() {
    	return mapClone(requestJson.get(RULESNEW));
    }

    public static Map<String, Object> getVerifyNewReqTemplate() {
    	return mapClone(requestJson.get(VERIFYNEW));
    }

    public static Map<String, Object> getOpenRulesReqTemplate() {
    	return mapClone(requestJson.get(OPENRULES));
    }

    public static Map<String, Object> getOpenUpgradeReqTemplate() {
    	return mapClone(requestJson.get(OPENUPGRADE));
    }

    public static Map<String, Object> getPayNewReqTemplate() {
    	return mapClone(requestJson.get(PAYNEW));
    }

    public static Map<String, Object> getQueryNewReqTemplate() {
    	return mapClone(requestJson.get(QUERYNEW));
    }

    public static Map<String, Object> getSmsNewReqTemplate() {
    	return mapClone(requestJson.get(SMSNEW));
    }

    public static Map<String, Object> getUnbindCardNewReqTemplate() {
    	return mapClone(requestJson.get(UNBINDCARDNEW));
    }

    public static Map<String, Object> getFollowRulesReqTemplate() {
    	return mapClone(requestJson.get(FOLLOWRULES));
    }
    
	public static Map<String,Object> mapClone(Map<String,Object> req){
	    Map<String,Object> map = new HashMap<String, Object>();
        for (String key : req.keySet()) {
            Object value = req.get(key);
            if ("params".equals(key)){
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
	
	public static void main(String[] args) {
		System.out.println(System.getProperty("user.dir"));
		init("RequestTemplate.conf");
	}
}
