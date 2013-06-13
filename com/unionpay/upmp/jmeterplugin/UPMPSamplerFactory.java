package com.unionpay.upmp.jmeterplugin;

import org.apache.jmeter.util.JMeterUtils;
import org.apache.jorphan.util.JOrphanUtils;

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

    public static final String DEFAULT_CLASSNAME =
        JMeterUtils.getPropDefault("jmeter.httpsampler", IMPL_HTTP_CLIENT4); //$NON-NLS-1$

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
        if (alias.equals(HTTP_SAMPLER_JAVA) || alias.equals(IMPL_JAVA)) {
            return new UPMPSamplerProxy(IMPL_JAVA);
        }
        if (alias.equals(HTTP_SAMPLER_APACHE) || alias.equals(IMPL_HTTP_CLIENT3_1)) {
            return new UPMPSamplerProxy(IMPL_HTTP_CLIENT3_1);
        }
        if (alias.equals(IMPL_HTTP_CLIENT4)) {
            return new UPMPSamplerProxy(IMPL_HTTP_CLIENT4);
        }
        throw new IllegalArgumentException("Unknown sampler type: '" + alias+"'");
    }

    public static String[] getImplementations(){
        return new String[]{IMPL_HTTP_CLIENT4,IMPL_HTTP_CLIENT3_1,IMPL_JAVA};
    }

    public static UPMPAbstractImpl getImplementation(String impl, UPMPSamplerBase base){
//        if (UPMPSamplerBase.PROTOCOL_FILE.equals(base.getProtocol())) {
//            return new HTTPFileImpl(base);
//        }
        if (JOrphanUtils.isBlank(impl)){
            impl = DEFAULT_CLASSNAME;
        }
        
        return new UPMPInsImpl(base);
//        if (IMPL_JAVA.equals(impl) || HTTP_SAMPLER_JAVA.equals(impl)) {
//            return new HTTPJavaImpl(base);
//        } else if (IMPL_HTTP_CLIENT3_1.equals(impl) || HTTP_SAMPLER_APACHE.equals(impl)) {
//            return new HTTPHC3Impl(base);                
//        } else if (IMPL_HTTP_CLIENT4.equals(impl)) {
//            return new HTTPHC4Impl(base);
//        } else {
//            throw new IllegalArgumentException("Unknown implementation type: '"+impl+"'");
//        }
    }

}
