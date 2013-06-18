package com.unionpay.upmp.jmeterplugin;

import org.apache.jorphan.util.JOrphanUtils;

import com.unionpay.upmp.util.UPMPConstant;

public class UPMPSamplerFactory {
    // N.B. These values are used in jmeter.properties (jmeter.httpsampler) - do not change
    // They can alse be used as the implementation name
    /** Use the the default Java HTTP implementation */
    public static final String HTTP_SAMPLER_JAVA = "UPMPSampler"; //$NON-NLS-1$

    /** Use Apache HTTPClient HTTP implementation */
    public static final String HTTP_SAMPLER_APACHE = "UPMPSampler2"; //$NON-NLS-1$

    //+ JMX implementation attribute values (also displayed in GUI) - do not change
    public static final String IMPL_HTTP_CLIENT4 = "UPMPClient4";  // $NON-NLS-1$

    public static final String IMPL_HTTP_CLIENT3_1 = "UPMPClient3.1"; // $NON-NLS-1$
    
    public static final String IMPL_JAVA = "Java"; // $NON-NLS-1$
    //- JMX

    public static final String IMPL_UPMP_MERCHANT = "UPMPMerchant";  // $NON-NLS-1$

    public static final String IMPL_UPMP_INS = "UPMPIns"; // $NON-NLS-1$
    
    public static final String IMPL_UPMP_MOBILE = "UPMPMobile"; // $NON-NLS-1$
    
    public static final String DEFAULT_CLASSNAME = UPMPConstant.DEFAULT_CLASSNAME; //$NON-NLS-1$

    private UPMPSamplerFactory() {
        // Not intended to be instantiated
    }

    /**
     * Create a new instance of the default sampler
     *
     * @return instance of default sampler
     */
    public static UPMPSamplerBase newInstance() {
        return newInstance(DEFAULT_CLASSNAME);
    }

    /**
     * Create a new instance of the required sampler type
     *
     * @param alias HTTP_SAMPLER or HTTP_SAMPLER_APACHE or IMPL_HTTP_CLIENT3_1 or IMPL_HTTP_CLIENT4
     * @return the appropriate sampler
     * @throws UnsupportedOperationException if alias is not recognised
     */
    public static UPMPSamplerBase newInstance(String alias) {
        if (alias ==null || alias.length() == 0) {
            return new UPMPSamplerProxy();
        }
        if (alias.equals(HTTP_SAMPLER_JAVA) || alias.equals(IMPL_UPMP_MERCHANT)) {
            return new UPMPSamplerProxy(IMPL_UPMP_MERCHANT);
        }
        if (alias.equals(HTTP_SAMPLER_APACHE) || alias.equals(IMPL_UPMP_INS)) {
            return new UPMPSamplerProxy(IMPL_UPMP_INS);
        }
        if (alias.equals(IMPL_UPMP_MOBILE)) {
            return new UPMPSamplerProxy(IMPL_UPMP_MOBILE);
        }
        throw new IllegalArgumentException("Unknown sampler type: '" + alias+"'");
    }

    public static String[] getImplementations(){
        return new String[]{IMPL_UPMP_MERCHANT,IMPL_UPMP_INS,IMPL_UPMP_MOBILE};
    }

    public static UPMPAbstractImpl getImplementation(String impl, UPMPSamplerBase base){
        if (JOrphanUtils.isBlank(impl)){
            impl = DEFAULT_CLASSNAME;
        }
        
        if (IMPL_UPMP_MERCHANT.equals(impl) || HTTP_SAMPLER_JAVA.equals(impl)) {
            return new UPMPMerImpl(base);
        } else if (IMPL_UPMP_INS.equals(impl) || HTTP_SAMPLER_APACHE.equals(impl)) {
            return new UPMPInsImpl(base);                
        } else if (IMPL_UPMP_MOBILE.equals(impl)) {
            return new UPMPMobileImpl(base);
        } else {
            throw new IllegalArgumentException("Unknown implementation type: '"+impl+"'");
        }
    }

}
