package com.unionpay.upmp.jmeterplugin;

import java.util.Map;

import com.unionpay.upmp.util.BytesUtil;
import com.unionpay.upmp.util.RequestTemplate;
import com.unionpay.upmp.util.SecurityUtil;

public class UPMPMobileMessageBuilder {
	
	static String KEY_INITKEY 			= "initkey";
	static String KEY_PARAMS 			= "params";
	static String KEY_TN 				= "tn";
	static String KEY_SECRET 			= "secret";
	static String KEY_PAN 				= "pan";
	static String KEY_SECURE_KEY		= "secure_key";
//	static String KEY_USER 				= "user";
//	static String KEY_LOCAL 			= "local";
//	static String KEY_TERMINAL_TYPE 	= "terminal_type";
//	static String KEY_TERMINAL_VERSION 	= "terminal_version";
//	static String KEY_OS_NAME 			= "os_name";
//	static String KEY_OS_VERSION 		= "os_version";
//	static String KEY_CARD_TYPE 		= "card_tp";
//	static String KEY_BANK 				= "bank";
//	static String KEY_MOBILE 			= "mobile";
	
	
	public static String BuildMessage(Map<String, String> req, String type) {
		RequestTemplate.init("RequestTemplate.conf");
		String Message = "";
		switch (type) {
		case RequestTemplate.INIT 			: Message = buildInit(req); break;
		case RequestTemplate.RULES 			: Message = buildRules(req); break;
		case RequestTemplate.RULES2P1 		: Message = buildRules2p1(req); break;
		case RequestTemplate.SMS 			: Message = buildSMS(req); break;
		case RequestTemplate.UNBINDCARD 	: Message = buildUnbind(req); break;
		case RequestTemplate.ENTRUST		: Message = buildEntrust(req); break;
		case RequestTemplate.VERIFY			: Message = buildVerify(req); break;
		case RequestTemplate.PAY			: Message = buildPay(req); break;
		case RequestTemplate.PAYNEW			: Message = buildPayNew(req); break;
		case RequestTemplate.FOLLOWRULES	: Message = buildFollowRules(req); break;
		case RequestTemplate.ENTRUSTNEW		: Message = buildEntrustNew(req); break;
		case RequestTemplate.BANKS			: Message = buildBanks(req); break;
		case RequestTemplate.MOREBANKS		: Message = buildMoreBanks(req); break;
		case RequestTemplate.OPENRULES		: Message = buildOpenRules(req); break;
		case RequestTemplate.OPENUPGRADE	: Message = buildOpenUpgrade(req); break;
		case RequestTemplate.QUERY			: Message = buildQuery(req); break;
		case RequestTemplate.QUERYNEW		: Message = buildQueryNew(req); break;
		case RequestTemplate.RULESNEW		: Message = buildRulesNew(req); break;
		case RequestTemplate.SMSNEW			: Message = buildSMSNew(req); break;
		case RequestTemplate.UNBINDCARDNEW	: Message = buildUnbindNew(req); break;
		case RequestTemplate.VERIFYNEW		: Message = buildVerifyNew(req); break;
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
		return SecurityUtil.encrypt(key, initReq);
	}
		
	private static String buildRules(Map<String, String> req){
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
	
		Map<String,Object> initReq = RequestTemplate.getRulesReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> initParams= (Map<String, Object>) initReq.get(KEY_PARAMS);
		
		initParams.putAll(req);
		return SecurityUtil.encrypt(key, initReq);
	}
	
	private static String buildRules2p1(Map<String, String> req){
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
	
		Map<String,Object> initReq = RequestTemplate.getRules2p1ReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> initParams= (Map<String, Object>) initReq.get(KEY_PARAMS);
		
		initParams.putAll(req);
		
		return SecurityUtil.encrypt(key, initReq);
	}
	
	private static String buildSMS(Map<String, String> req){
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
		req.remove(KEY_SECRET);
	
		Map<String,Object> smsReq = RequestTemplate.getSmsReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> smsParams= (Map<String, Object>) smsReq.get(KEY_PARAMS);
		
		smsParams.putAll(req);
		
		return SecurityUtil.encrypt(key, smsReq);
	}
	
	private static String buildUnbind(Map<String, String> req){
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
	
		Map<String,Object> initReq = RequestTemplate.getUnbindCardReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> initParams= (Map<String, Object>) initReq.get(KEY_PARAMS);
		
		initParams.put(KEY_PAN, req.get(KEY_PAN));
		
		return SecurityUtil.encrypt(key, initReq);
	}
	
	private static String buildEntrust(Map<String, String> req){
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
		
		Map<String,Object> initReq = RequestTemplate.getEntrustReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> initParams= (Map<String, Object>) initReq.get(KEY_PARAMS);
		
		req.remove(KEY_SECRET);
		initParams.putAll(req);
		
		return SecurityUtil.encrypt(key, initReq);
	}
	
	private static String buildVerify(Map<String, String> req){
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
		
		Map<String,Object> initReq = RequestTemplate.getVerifyReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> initParams= (Map<String, Object>) initReq.get(KEY_PARAMS);
		
		initParams.putAll(req);	
		return SecurityUtil.encrypt(key, initReq);
	}
	
	private static String buildPay(Map<String, String> req) {
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
		
		Map<String,Object> payReq = RequestTemplate.getPayReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> initParams= (Map<String, Object>) payReq.get(KEY_PARAMS);
		
		initParams.putAll(req);	
		return SecurityUtil.encrypt(key, payReq);
	}
	
	private static String buildPayNew(Map<String, String> req) {
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
		
		Map<String,Object> payReq = RequestTemplate.getPayNewReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> initParams= (Map<String, Object>) payReq.get(KEY_PARAMS);
		
		initParams.putAll(req);	
		return SecurityUtil.encrypt(key, payReq);
	}
	
	private static String buildFollowRules(Map<String, String> req) {
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
		
		Map<String,Object> payReq = RequestTemplate.getFollowRulesReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> initParams= (Map<String, Object>) payReq.get(KEY_PARAMS);
		
		initParams.putAll(req);	
		return SecurityUtil.encrypt(key, payReq);
	}
	
	private static String buildEntrustNew(Map<String, String> req) {
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
		
		Map<String,Object> payReq = RequestTemplate.getEntrustNewReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> initParams= (Map<String, Object>) payReq.get(KEY_PARAMS);
		
		initParams.putAll(req);	
		return SecurityUtil.encrypt(key, payReq);
	}
	
    /**
     * build banks message
     * no param
     */
	private static String buildBanks(Map<String, String> req) {
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
		
		Map<String,Object> payReq = RequestTemplate.getBanksReqTemplate();
		
		return SecurityUtil.encrypt(key, payReq);
	}
		
    /**
     * build morebanks message
     * @param card_tp
     * @param start
     */
	private static String buildMoreBanks(Map<String, String> req) {
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
		
		Map<String,Object> payReq = RequestTemplate.getMoreBanksReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> initParams= (Map<String, Object>) payReq.get(KEY_PARAMS);
		initParams.putAll(req);	
		return SecurityUtil.encrypt(key, payReq);
	}
	
    /**
     * build openrules message
     * @param first_pay_flag
     * @param if first_pay_flag == 0 pan
     * @param if first_pay_flag == 1 card
     */
	private static String buildOpenRules(Map<String, String> req) {
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
		
		Map<String,Object> openRulesReq = RequestTemplate.getOpenRulesReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> openRulesParams= (Map<String, Object>) openRulesReq.get(KEY_PARAMS);
		openRulesParams.remove("pan");
	    openRulesParams.remove("card");
	    openRulesParams.putAll(req);	
		return SecurityUtil.encrypt(key, openRulesReq);
	}
	
    /**
     * build OpenUpgrade message
     * @param all in req
     */
	private static String buildOpenUpgrade(Map<String, String> req) {
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
		
		Map<String,Object> openRulesReq = RequestTemplate.getOpenUpgradeReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> openRulesParams= (Map<String, Object>) openRulesReq.get(KEY_PARAMS);
	    openRulesParams.putAll(req);	
		return SecurityUtil.encrypt(key, openRulesReq);
	}
	
    /**
     * build Query message
     * @param qn
     * @param type
     */
	private static String buildQuery(Map<String, String> req) {
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
		
		Map<String,Object> openRulesReq = RequestTemplate.getQueryReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> openRulesParams= (Map<String, Object>) openRulesReq.get(KEY_PARAMS);
	    openRulesParams.putAll(req);	
		return SecurityUtil.encrypt(key, openRulesReq);
	}
	
    /**
     * build QueryNew message
     * @param qn
     * @param type
     */
	private static String buildQueryNew(Map<String, String> req) {
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
		
		Map<String,Object> openRulesReq = RequestTemplate.getQueryNewReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> openRulesParams= (Map<String, Object>) openRulesReq.get(KEY_PARAMS);
	    openRulesParams.putAll(req);	
		return SecurityUtil.encrypt(key, openRulesReq);
	}
	
    /**
     * build RulesNew message
     * @param first_pay_flag
     * @param pan
     * @param card
     * @param pay_mode
     */
	private static String buildRulesNew(Map<String, String> req) {
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
		
		Map<String,Object> rulesNewReq = RequestTemplate.getRulesNewReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> rulesNewParams= (Map<String, Object>) rulesNewReq.get(KEY_PARAMS);
		rulesNewParams.putAll(req);	
		return SecurityUtil.encrypt(key, rulesNewReq);
	}
	
    /**
     * build SMSNew message
     * @param first_pay_flag
     * @param mobile
     * @param if first_pay_flag == 0 pan
     * @param if first_pay_flag == 1 card
     */
	private static String buildSMSNew(Map<String, String> req) {
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
		
		Map<String,Object> smsNewReq = RequestTemplate.getSmsNewReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> smsNewParams= (Map<String, Object>) smsNewReq.get(KEY_PARAMS);
		smsNewParams.putAll(req);	
		return SecurityUtil.encrypt(key, smsNewReq);
	}
	
    /**
     * build UnbindNew message
     * @param card
     */
	private static String buildUnbindNew(Map<String, String> req) {
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
		
		Map<String,Object> unbindReq = RequestTemplate.getUnbindCardNewReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> unbindParams= (Map<String, Object>) unbindReq.get(KEY_PARAMS);
		unbindParams.putAll(req);	
		return SecurityUtil.encrypt(key, unbindReq);
	}
	
    /**
     * build VerifyNew message
     * @param all in req
     */
	private static String buildVerifyNew(Map<String, String> req) {
		byte[] key = BytesUtil.hexToBytes(req.get(KEY_SECRET));
		
		Map<String,Object> verifyNewReq = RequestTemplate.getVerifyNewReqTemplate();
		@SuppressWarnings("unchecked")
		Map<String, Object> verifyNewParams= (Map<String, Object>) verifyNewReq.get(KEY_PARAMS);
		verifyNewParams.putAll(req);	
		return SecurityUtil.encrypt(key, verifyNewReq);
	}
	

}
