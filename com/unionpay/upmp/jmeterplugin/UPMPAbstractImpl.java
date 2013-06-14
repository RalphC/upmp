package com.unionpay.upmp.jmeterplugin;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;

import org.apache.jmeter.JMeter;
import org.apache.jmeter.config.Arguments;
import org.apache.jmeter.protocol.http.control.AuthManager;
import org.apache.jmeter.protocol.http.control.CacheManager;
import org.apache.jmeter.protocol.http.control.CookieManager;
import org.apache.jmeter.protocol.http.control.HeaderManager;
import org.apache.jmeter.samplers.Interruptible;
import org.apache.jmeter.samplers.SampleResult;
import org.apache.jmeter.util.JMeterUtils;
import org.apache.jorphan.logging.LoggingManager;
import org.apache.jorphan.util.JOrphanUtils;
import org.apache.log.Logger;

import com.unionpay.upmp.util.HTTPConstantsInterface;
import com.unionpay.upmp.util.HTTPFileArg;

public abstract class UPMPAbstractImpl implements Interruptible, HTTPConstantsInterface{

	protected final UPMPSamplerBase testElement;
    
    private static final Logger log = LoggingManager.getLoggerForClass();

    protected static final String PROXY_HOST = System.getProperty("http.proxyHost","");

    protected static final String NONPROXY_HOSTS = System.getProperty("http.nonProxyHosts","");

    protected static final int PROXY_PORT = Integer.parseInt(System.getProperty("http.proxyPort","0"));

    protected static final boolean PROXY_DEFINED = PROXY_HOST.length() > 0 && PROXY_PORT > 0;

    protected static final String PROXY_USER = JMeterUtils.getPropDefault(JMeter.HTTP_PROXY_USER,"");

    protected static final String PROXY_PASS = JMeterUtils.getPropDefault(JMeter.HTTP_PROXY_PASS,"");

    protected static final String PROXY_DOMAIN = JMeterUtils.getPropDefault("http.proxyDomain","");

    protected static final InetAddress localAddress;

    protected static final String localHost;

    protected static final Set<String> nonProxyHostFull = new HashSet<String>();

    protected static final List<String> nonProxyHostSuffix = new ArrayList<String>();

    protected static final int nonProxyHostSuffixSize;

    protected static final int CPS_HTTP = JMeterUtils.getPropDefault("httpclient.socket.http.cps", 0);
    
    protected static final int CPS_HTTPS = JMeterUtils.getPropDefault("httpclient.socket.https.cps", 0);

    protected static final boolean USE_LOOPBACK = JMeterUtils.getPropDefault("httpclient.loopback", false);
    
    protected static final String HTTP_VERSION = JMeterUtils.getPropDefault("httpclient.version", "1.1");

    // -1 means not defined
    protected static final int SO_TIMEOUT = JMeterUtils.getPropDefault("httpclient.timeout", -1);

    static {
        if (NONPROXY_HOSTS.length() > 0){
            StringTokenizer s = new StringTokenizer(NONPROXY_HOSTS,"|");// $NON-NLS-1$
            while (s.hasMoreTokens()){
                String t = s.nextToken();
                if (t.indexOf('*') ==0){// e.g. *.apache.org // $NON-NLS-1$
                    nonProxyHostSuffix.add(t.substring(1));
                } else {
                    nonProxyHostFull.add(t);// e.g. www.apache.org
                }
            }
        }
        nonProxyHostSuffixSize=nonProxyHostSuffix.size();

        InetAddress inet=null;
        String localHostOrIP =
            JMeterUtils.getPropDefault("httpclient.localaddress",""); // $NON-NLS-1$
        if (localHostOrIP.length() > 0){
            try {
                inet = InetAddress.getByName(localHostOrIP);
                log.info("Using localAddress "+inet.getHostAddress());
            } catch (UnknownHostException e) {
                log.warn(e.getLocalizedMessage());
            }
        } else {
            try {
                InetAddress addr = InetAddress.getLocalHost();
                // Get hostname
                localHostOrIP = addr.getHostName();
            } catch (UnknownHostException e) {
                log.warn("Cannot determine localhost name, and httpclient.localaddress was not specified");
            }
        }
        localAddress = inet;
        localHost = localHostOrIP;
        log.info("Local host = "+localHost);

    }

    protected static boolean isNonProxy(String host){
        return nonProxyHostFull.contains(host) || isPartialMatch(host);
    }

    protected static boolean isPartialMatch(String host) {
        for (int i=0;i<nonProxyHostSuffixSize;i++){
            if (host.endsWith(nonProxyHostSuffix.get(i))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Is a dynamic proxy defined?
     *
     * @param proxyHost the host to check
     * @param proxyPort the port to check
     * @return {@code true} iff both ProxyPort and ProxyHost are defined.
     */
    protected boolean isDynamicProxy(String proxyHost, int proxyPort){
        return (!JOrphanUtils.isBlank(proxyHost) && proxyPort > 0);        
    }

    /**
     * Is a static proxy defined?
     * 
     * @param host to check against non-proxy hosts
     * @return {@code true} iff a static proxy has been defined.
     */
    protected static boolean isStaticProxy(String host){
        return PROXY_DEFINED && !isNonProxy(host);
    }
    
    /**
     * @param value String value to test
     * @return true if value is null or empty trimmed
     */
    protected static boolean isNullOrEmptyTrimmed(String value) {
        return JOrphanUtils.isBlank(value);
    }
    
    protected UPMPAbstractImpl(UPMPSamplerBase testElement){
        this.testElement = testElement;
    }

    protected abstract UPMPSampleResult sample(URL url, String method, boolean areFollowingRedirect, int frameDepth);

    // Allows HTTPSamplerProxy to call threadFinished; subclasses can override if necessary
    protected void threadFinished() {
    }

    // Provide access to HTTPSamplerBase methods
    
    /**
     * Invokes {@link HTTPSamplerBase#errorResult(Throwable, UPMPSampleResult)}
     */
    protected UPMPSampleResult errorResult(Throwable t, UPMPSampleResult res) {
        return testElement.errorResult(t, res);
    }

    /**
     * Invokes {@link HTTPSamplerBase#getArguments()}
     */
    protected Arguments getArguments() {
        return testElement.getArguments();
    }

    /**
     * Invokes {@link HTTPSamplerBase#getAuthManager()}
     */
    protected AuthManager getAuthManager() {
        return testElement.getAuthManager();
    }

    /**
     * Invokes {@link HTTPSamplerBase#getAutoRedirects()}
     */
    protected boolean getAutoRedirects() {
        return testElement.getAutoRedirects();
    }

    /**
     * Invokes {@link HTTPSamplerBase#getCacheManager()}
     */
    protected CacheManager getCacheManager() {
        return testElement.getCacheManager();
    }

    /**
     * Invokes {@link HTTPSamplerBase#getConnectTimeout()}
     */
    protected int getConnectTimeout() {
        return testElement.getConnectTimeout();
    }

    /**
     * Invokes {@link HTTPSamplerBase#getContentEncoding()}
     * @return the encoding of the content, i.e. its charset name
     */
    protected String getContentEncoding() {
        return testElement.getContentEncoding();
    }

    /**
     * Invokes {@link HTTPSamplerBase#getCookieManager()}
     */
    protected CookieManager getCookieManager() {
        return testElement.getCookieManager();
    }

    /**
     * Invokes {@link HTTPSamplerBase#getHeaderManager()}
     */
    protected HeaderManager getHeaderManager() {
        return testElement.getHeaderManager();
    }

    /**
     * Invokes {@link HTTPSamplerBase#getHTTPFiles()}
     */
    protected HTTPFileArg[] getHTTPFiles() {
        return testElement.getHTTPFiles();
    }

    /**
     * Invokes {@link HTTPSamplerBase#getIpSource()}
     */
    protected String getIpSource() {
        return testElement.getIpSource();
    }

    /**
     * Invokes {@link HTTPSamplerBase#getProxyHost()}
     */
    protected String getProxyHost() {
        return testElement.getProxyHost();
    }

    /**
     * Invokes {@link HTTPSamplerBase#getProxyPass()}
     */
    protected String getProxyPass() {
        return testElement.getProxyPass();
    }

    /**
     * Invokes {@link HTTPSamplerBase#getProxyPortInt()}
     */
    protected int getProxyPortInt() {
        return testElement.getProxyPortInt();
    }

    /**
     * Invokes {@link HTTPSamplerBase#getProxyUser()}
     */
    protected String getProxyUser() {
        return testElement.getProxyUser();
    }

    /**
     * Invokes {@link HTTPSamplerBase#getResponseTimeout()}
     */
    protected int getResponseTimeout() {
        return testElement.getResponseTimeout();
    }

    /**
     * Determine whether to send a file as the entire body of an
     * entity enclosing request such as POST, PUT or PATCH.
     * 
     * Invokes {@link HTTPSamplerBase#getSendFileAsPostBody()}
     */
    protected boolean getSendFileAsPostBody() {
        return testElement.getSendFileAsPostBody();
    }

    /**
     * Determine whether to send concatenated parameters as the entire body of an
     * entity enclosing request such as POST, PUT or PATCH.
     * 
     * Invokes {@link HTTPSamplerBase#getSendParameterValuesAsPostBody()}
     */
    protected boolean getSendParameterValuesAsPostBody() {
        return testElement.getSendParameterValuesAsPostBody();
    }

    /**
     * Invokes {@link HTTPSamplerBase#getUseKeepAlive()}
     */
    protected boolean getUseKeepAlive() {
        return testElement.getUseKeepAlive();
    }

    /**
     * Invokes {@link HTTPSamplerBase#getUseMultipartForPost()}
     */
    protected boolean getUseMultipartForPost() {
        return testElement.getUseMultipartForPost();
    }

    /**
     * Invokes {@link HTTPSamplerBase#getDoBrowserCompatibleMultipart()}
     */
    protected boolean getDoBrowserCompatibleMultipart() {
        return testElement.getDoBrowserCompatibleMultipart();
    }

    /**
     * Invokes {@link HTTPSamplerBase#hasArguments()}
     */
    protected boolean hasArguments() {
        return testElement.hasArguments();
    }

    /**
     * Invokes {@link HTTPSamplerBase#isMonitor()}
     */
    protected boolean isMonitor() {
        return testElement.isMonitor();
    }

    /**
     * Invokes {@link HTTPSamplerBase#isSuccessCode(int)}
     */
    protected boolean isSuccessCode(int errorLevel) {
        return testElement.isSuccessCode(errorLevel);
    }

    /**
     * Invokes {@link HTTPSamplerBase#readResponse(SampleResult, InputStream, int)}
     */
    protected byte[] readResponse(SampleResult res, InputStream instream,
            int responseContentLength) throws IOException {
        return testElement.readResponse(res, instream, responseContentLength);
    }

    /**
     * Invokes {@link HTTPSamplerBase#readResponse(SampleResult, InputStream, int)}
     */
    protected byte[] readResponse(SampleResult res, BufferedInputStream in,
            int contentLength) throws IOException {
        return testElement.readResponse(res, in, contentLength);
    }

    /**
     * Invokes {@link HTTPSamplerBase#resultProcessing(boolean, int, HTTPSampleResult)}
     */
    protected UPMPSampleResult resultProcessing(boolean areFollowingRedirect,
            int frameDepth, UPMPSampleResult res) {
        return testElement.resultProcessing(areFollowingRedirect, frameDepth, res);
    }

    /**
     * Invokes {@link HTTPSamplerBase#setUseKeepAlive(boolean)}
     */
    protected void setUseKeepAlive(boolean b) {
        testElement.setUseKeepAlive(b);
    }

    /**
     * Called by testIterationStart if the SSL Context was reset.
     * 
     * This implementation does nothing.
     */
    protected void notifySSLContextWasReset() {
        // NOOP
    }
}
