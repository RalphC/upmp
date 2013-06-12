package com.unionpay.upmp.jmeterplugin;

import java.net.URL;
import org.apache.jmeter.samplers.Interruptible;

public final class UPMPSamplerProxy extends UPMPSamplerBase implements Interruptible {

    private static final long serialVersionUID = 1L;

    private transient UPMPAbstractImpl impl;
    
    public UPMPSamplerProxy(){
        super();
    }
    
    /**
     * Convenience method used to initialise the implementation.
     * 
     * @param impl the implementation to use.
     */
    public UPMPSamplerProxy(String impl){
        super();
        setImplementation(impl);
    }
        
    /** {@inheritDoc} */
    @Override
    protected UPMPSampleResult sample(URL u, String method, boolean areFollowingRedirect, int depth) {
        if (impl == null) { // Not called from multiple threads, so this is OK
            try {
                impl = UPMPSamplerFactory.getImplementation(getImplementation(), this);
            } catch (Exception ex) {
                return errorResult(ex, new UPMPSampleResult());
            }
        }
        return impl.sample(u, method, areFollowingRedirect, depth);
    }

    // N.B. It's not possible to forward threadStarted() to the implementation class.
    // This is because Config items are not processed until later, and HTTPDefaults may define the implementation

    @Override
    public void threadFinished(){
        if (impl != null){
            impl.threadFinished(); // Forward to sampler
        }
    }

    @Override
    public boolean interrupt() {
        if (impl != null) {
            return impl.interrupt(); // Forward to sampler
        }
        return false;
    }

    /**
     * {@inheritDoc}
     * This implementation forwards to the implementation class.
     */
    @Override
    protected void notifySSLContextWasReset() {
        if (impl != null) {
            impl.notifySSLContextWasReset();
        }
    }
}
