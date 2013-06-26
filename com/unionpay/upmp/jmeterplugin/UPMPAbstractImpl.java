package com.unionpay.upmp.jmeterplugin;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.Header;
import org.apache.http.HttpConnection;
import org.apache.http.HttpConnectionMetrics;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.NTCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.client.params.CookiePolicy;
import org.apache.http.client.protocol.ResponseContentEncoding;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.impl.client.AbstractHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.CoreConnectionPNames;
import org.apache.http.params.CoreProtocolPNames;
import org.apache.http.params.DefaultedHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.ExecutionContext;
import org.apache.http.protocol.HttpContext;
import org.apache.jmeter.JMeter;
import org.apache.jmeter.config.Arguments;
import org.apache.jmeter.protocol.http.control.AuthManager;
import org.apache.jmeter.protocol.http.control.Authorization;
import org.apache.jmeter.protocol.http.control.CacheManager;
import org.apache.jmeter.protocol.http.control.CookieManager;
import org.apache.jmeter.protocol.http.control.HeaderManager;
import org.apache.jmeter.protocol.http.sampler.HttpClientDefaultParameters;
import org.apache.jmeter.protocol.http.util.HC4TrustAllSSLSocketFactory;
import org.apache.jmeter.protocol.http.util.SlowHC4SSLSocketFactory;
import org.apache.jmeter.protocol.http.util.SlowHC4SocketFactory;
import org.apache.jmeter.samplers.Interruptible;
import org.apache.jmeter.samplers.SampleResult;
import org.apache.jmeter.testelement.property.CollectionProperty;
import org.apache.jmeter.testelement.property.PropertyIterator;
import org.apache.jmeter.util.JMeterUtils;
import org.apache.jorphan.logging.LoggingManager;
import org.apache.jorphan.util.JOrphanUtils;
import org.apache.log.Logger;

import com.unionpay.upmp.util.HTTPConstantsInterface;
import com.unionpay.upmp.util.HTTPFileArg;
import com.unionpay.upmp.util.UPMPConstant;

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
    
    // Scheme used for slow HTTP sockets. Cannot be set as a default, because must be set on an HttpClient instance.
    protected static final Scheme SLOW_HTTP;
    
    // We always want to override the HTTPS scheme, because we want to trust all certificates and hosts
    protected static final Scheme HTTPS_SCHEME;
    
    /*
     * Create a set of default parameters from the ones initially created.
     * This allows the defaults to be overridden if necessary from the properties file.
     */
    protected static final HttpParams DEFAULT_HTTP_PARAMS;
    
    /** retry count to be used (default 1); 0 = disable retries */
    protected static final int RETRY_COUNT = 0;

    protected static final String CONTEXT_METRICS = "jmeter_metrics"; // TODO hack, to be removed later
    
    protected volatile HttpUriRequest currentRequest; // Accessed from multiple threads

    protected static final HttpResponseInterceptor METRICS_SAVER = new HttpResponseInterceptor(){
        @Override
        public void process(HttpResponse response, HttpContext context)
                throws HttpException, IOException {
            HttpConnection conn = (HttpConnection) context.getAttribute(ExecutionContext.HTTP_CONNECTION);
            HttpConnectionMetrics metrics = conn.getMetrics();
            context.setAttribute(CONTEXT_METRICS, metrics);
        }
    };
    protected static final HttpRequestInterceptor METRICS_RESETTER = new HttpRequestInterceptor() {
		@Override
        public void process(HttpRequest request, HttpContext context)
				throws HttpException, IOException {
            HttpConnection conn = (HttpConnection) context.getAttribute(ExecutionContext.HTTP_CONNECTION);
			HttpConnectionMetrics metrics = conn.getMetrics();
			metrics.reset();
		}
	};
    
    protected static final ThreadLocal<Map<HttpClientKey, HttpClient>> HTTPCLIENTS = 
            new ThreadLocal<Map<HttpClientKey, HttpClient>>(){
            @Override
            protected Map<HttpClientKey, HttpClient> initialValue() {
                return new HashMap<HttpClientKey, HttpClient>();
            }
        };

        
        /**
         * Holder class for all fields that define an HttpClient instance;
         * used as the key to the ThreadLocal map of HttpClient instances.
         */
        protected static final class HttpClientKey {

        	protected final String target; // protocol://[user:pass@]host:[port]
        	protected final boolean hasProxy;
        	protected final String proxyHost;
        	protected final int proxyPort;
        	protected final String proxyUser;
        	protected final String proxyPass;
            
        	protected final int hashCode; // Always create hash because we will always need it

            /**
             * @param url URL Only protocol and url authority are used (protocol://[user:pass@]host:[port])
             * @param hasProxy has proxy
             * @param proxyHost proxy host
             * @param proxyPort proxy port
             * @param proxyUser proxy user
             * @param proxyPass proxy password
             */
            public HttpClientKey(URL url, boolean hasProxy, String proxyHost,
                    int proxyPort, String proxyUser, String proxyPass) {
                // N.B. need to separate protocol from authority otherwise http://server would match https://erver
                // could use separate fields, but simpler to combine them
                this.target = url.getProtocol()+"://"+url.getAuthority();
                this.hasProxy = hasProxy;
                this.proxyHost = proxyHost;
                this.proxyPort = proxyPort;
                this.proxyUser = proxyUser;
                this.proxyPass = proxyPass;
                this.hashCode = getHash();
            }
            
            protected int getHash() {
                int hash = 17;
                hash = hash*31 + (hasProxy ? 1 : 0);
                if (hasProxy) {
                    hash = hash*31 + getHash(proxyHost);
                    hash = hash*31 + proxyPort;
                    hash = hash*31 + getHash(proxyUser);
                    hash = hash*31 + getHash(proxyPass);
                }
                hash = hash*31 + target.hashCode();
                return hash;
            }

            // Allow for null strings
            protected int getHash(String s) {
                return s == null ? 0 : s.hashCode(); 
            }
            
            @Override
            public boolean equals (Object obj){
                if (this == obj) {
                    return true;
                }
                if (!(obj instanceof HttpClientKey)) {
                    return false;
                }
                HttpClientKey other = (HttpClientKey) obj;
                if (this.hasProxy) { // otherwise proxy String fields may be null
                    return 
                    this.hasProxy == other.hasProxy &&
                    this.proxyPort == other.proxyPort &&
                    this.proxyHost.equals(other.proxyHost) &&
                    this.proxyUser.equals(other.proxyUser) &&
                    this.proxyPass.equals(other.proxyPass) &&
                    this.target.equals(other.target);
                }
                // No proxy, so don't check proxy fields
                return 
                    this.hasProxy == other.hasProxy &&
                    this.target.equals(other.target);
            }

            @Override
            public int hashCode(){
                return hashCode;
            }
        }
        
        protected HttpClient setupClient(URL url) {

        	Map<HttpClientKey, HttpClient> map = HTTPCLIENTS.get();

        	final String host = url.getHost();
        	final String proxyHost = getProxyHost();
        	final int proxyPort = getProxyPortInt();

        	boolean useStaticProxy = isStaticProxy(host);
        	boolean useDynamicProxy = isDynamicProxy(proxyHost, proxyPort);

        	// Lookup key - must agree with all the values used to create the HttpClient.
        	HttpClientKey key = new HttpClientKey(url, (useStaticProxy || useDynamicProxy), 
        			useDynamicProxy ? proxyHost : PROXY_HOST,
        					useDynamicProxy ? proxyPort : PROXY_PORT,
        							useDynamicProxy ? getProxyUser() : PROXY_USER,
        									useDynamicProxy ? getProxyPass() : PROXY_PASS);

        	HttpClient httpClient = map.get(key);

        	if (httpClient == null){ // One-time init for this client

        		HttpParams clientParams = new DefaultedHttpParams(new BasicHttpParams(), DEFAULT_HTTP_PARAMS);

        		httpClient = new DefaultHttpClient(clientParams){
        			@Override
        			protected HttpRequestRetryHandler createHttpRequestRetryHandler() {
        				return new DefaultHttpRequestRetryHandler(RETRY_COUNT, false); // set retry count
        			}
        		};
        		((AbstractHttpClient) httpClient).addResponseInterceptor(new ResponseContentEncoding());
        		((AbstractHttpClient) httpClient).addResponseInterceptor(METRICS_SAVER); // HACK
        		((AbstractHttpClient) httpClient).addRequestInterceptor(METRICS_RESETTER); 

        		// Override the defualt schemes as necessary
        		SchemeRegistry schemeRegistry = httpClient.getConnectionManager().getSchemeRegistry();

        		if (SLOW_HTTP != null){
        			schemeRegistry.register(SLOW_HTTP);
        		}

        		if (HTTPS_SCHEME != null){
        			schemeRegistry.register(HTTPS_SCHEME);
        		}

        		// Set up proxy details
        		if (useDynamicProxy){
        			HttpHost proxy = new HttpHost(proxyHost, proxyPort);
        			clientParams.setParameter(ConnRoutePNames.DEFAULT_PROXY, proxy);
        			String proxyUser = getProxyUser();

        			if (proxyUser.length() > 0) {                   
        				((AbstractHttpClient) httpClient).getCredentialsProvider().setCredentials(
        						new AuthScope(proxyHost, proxyPort),
        						new NTCredentials(proxyUser, getProxyPass(), localHost, PROXY_DOMAIN));
        			}
        		} else if (useStaticProxy) {
        			HttpHost proxy = new HttpHost(PROXY_HOST, PROXY_PORT);
        			clientParams.setParameter(ConnRoutePNames.DEFAULT_PROXY, proxy);
        			if (PROXY_USER.length() > 0) {
        				((AbstractHttpClient) httpClient).getCredentialsProvider().setCredentials(
        						new AuthScope(PROXY_HOST, PROXY_PORT),
        						new NTCredentials(PROXY_USER, PROXY_PASS, localHost, PROXY_DOMAIN));
        			}
        		}

        		// Bug 52126 - we do our own cookie handling
        		clientParams.setParameter(ClientPNames.COOKIE_POLICY, CookiePolicy.IGNORE_COOKIES);

        		if (log.isDebugEnabled()) {
        			log.debug("Created new HttpClient: @"+System.identityHashCode(httpClient));
        		}

        		map.put(key, httpClient); // save the agent for next time round
        	} else {
        		if (log.isDebugEnabled()) {
        			log.debug("Reusing the HttpClient: @"+System.identityHashCode(httpClient));
        		}
        	}

        	// TODO - should this be done when the client is created?
        	// If so, then the details need to be added as part of HttpClientKey
        	setConnectionAuthorization(httpClient, url, getAuthManager(), key);

        	return httpClient;
        }
        
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
        
        log.info("HTTP request retry count = "+RETRY_COUNT);
        
        // TODO use new setDefaultHttpParams(HttpParams params) static method when 4.1 is available
        final DefaultHttpClient dhc = new DefaultHttpClient();
        DEFAULT_HTTP_PARAMS = dhc.getParams(); // Get the default params
        dhc.getConnectionManager().shutdown(); // Tidy up
        
        // Process Apache HttpClient parameters file
        String file=JMeterUtils.getProperty("hc.parameters.file"); // $NON-NLS-1$
        if (file != null) {
            HttpClientDefaultParameters.load(file, DEFAULT_HTTP_PARAMS);
        }

        // Set up HTTP scheme override if necessary
        if (CPS_HTTP > 0) {
            log.info("Setting up HTTP SlowProtocol, cps="+CPS_HTTP);
            SLOW_HTTP = new Scheme(UPMPConstant.PROTOCOL_HTTP, UPMPConstant.DEFAULT_HTTP_PORT, new SlowHC4SocketFactory(CPS_HTTP));
        } else {
            SLOW_HTTP = null;
        }
        
        // We always want to override the HTTPS scheme
        Scheme https = null;
        if (CPS_HTTPS > 0) {
            log.info("Setting up HTTPS SlowProtocol, cps="+CPS_HTTPS);
            try {
                https = new Scheme(UPMPConstant.PROTOCOL_HTTPS, UPMPConstant.DEFAULT_HTTPS_PORT, new SlowHC4SSLSocketFactory(CPS_HTTPS));
            } catch (GeneralSecurityException e) {
                log.warn("Failed to initialise SLOW_HTTPS scheme, cps="+CPS_HTTPS, e);
            }
        } else {
            log.info("Setting up HTTPS TrustAll scheme");
            try {
                https = new Scheme(UPMPConstant.PROTOCOL_HTTPS, UPMPConstant.DEFAULT_HTTPS_PORT, new HC4TrustAllSSLSocketFactory());
            } catch (GeneralSecurityException e) {
                log.warn("Failed to initialise HTTPS TrustAll scheme", e);
            }
        }
        HTTPS_SCHEME = https;
        if (localAddress != null){
            DEFAULT_HTTP_PARAMS.setParameter(ConnRoutePNames.LOCAL_ADDRESS, localAddress);
        }

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
        log.debug("closeThreadLocalConnections called");
        closeThreadLocalConnections();
    }
    
    /**
     * 
     */
    protected void closeThreadLocalConnections() {
        // Does not need to be synchronised, as all access is from same thread
        Map<HttpClientKey, HttpClient> map = HTTPCLIENTS.get();
        if ( map != null ) {
            for ( HttpClient cl : map.values() ) {
            	((AbstractHttpClient) cl).clearRequestInterceptors(); 
            	((AbstractHttpClient) cl).clearResponseInterceptors(); 
                cl.getConnectionManager().shutdown();
            }
            map.clear();
        }
    }
    
    /**
     * Extracts all the required non-cookie headers for that particular URL request and
     * sets them in the <code>HttpMethod</code> passed in
     *
     * @param request
     *            <code>HttpRequest</code> which represents the request
     * @param url
     *            <code>URL</code> of the URL request
     * @param headerManager
     *            the <code>HeaderManager</code> containing all the cookies
     *            for this <code>UrlConfig</code>
     * @param cacheManager the CacheManager (may be null)
     */
    protected void setConnectionHeaders(HttpRequestBase request, URL url, HeaderManager headerManager, CacheManager cacheManager) {
    	if (headerManager != null) {
    		CollectionProperty headers = headerManager.getHeaders();
    		if (headers != null) {
    			PropertyIterator i = headers.iterator();
    			while (i.hasNext()) {
    				org.apache.jmeter.protocol.http.control.Header header
    				= (org.apache.jmeter.protocol.http.control.Header)
    				i.next().getObjectValue();
    				String n = header.getName();
    				// Don't allow override of Content-Length
    				// TODO - what other headers are not allowed?
    				if (! UPMPConstant.HEADER_CONTENT_LENGTH.equalsIgnoreCase(n)){
    					String v = header.getValue();
    					if (UPMPConstant.HEADER_HOST.equalsIgnoreCase(n)) {
    						int port = url.getPort();
    						v = v.replaceFirst(":\\d+$",""); // remove any port specification // $NON-NLS-1$ $NON-NLS-2$
    						if (port != -1) {
    							if (port == url.getDefaultPort()) {
    								port = -1; // no need to specify the port if it is the default
    							}
    						}
    						request.getParams().setParameter(ClientPNames.VIRTUAL_HOST, new HttpHost(v, port));
    					} else {
    						request.addHeader(n, v);
    					}
    				}
    			}
    		}
    	}
    	if (cacheManager != null){
    		cacheManager.setHeaders(url, request);
    	}
    }
    
    /**
     * Setup credentials for url AuthScope but keeps Proxy AuthScope credentials
     * @param client HttpClient
     * @param url URL
     * @param authManager {@link AuthManager}
     * @param key key
     */
    protected void setConnectionAuthorization(HttpClient client, URL url, AuthManager authManager, HttpClientKey key) {
        CredentialsProvider credentialsProvider = 
            ((AbstractHttpClient) client).getCredentialsProvider();
        if (authManager != null) {
            Authorization auth = authManager.getAuthForURL(url);
            if (auth != null) {
                    String username = auth.getUser();
                    String realm = auth.getRealm();
                    String domain = auth.getDomain();
                    if (log.isDebugEnabled()){
                        log.debug(username + " > D="+domain+" R="+realm);
                    }
                    credentialsProvider.setCredentials(
                            new AuthScope(url.getHost(), url.getPort(), realm.length()==0 ? null : realm),
                            new NTCredentials(username, auth.getPass(), localHost, domain));
            } else {
                credentialsProvider.clear();
            }
        } else {
            Credentials credentials = null;
            AuthScope authScope = null;
            if(key.hasProxy && !StringUtils.isEmpty(key.proxyUser)) {
                authScope = new AuthScope(key.proxyHost, key.proxyPort);
                credentials = credentialsProvider.getCredentials(authScope);
            }
            credentialsProvider.clear(); 
            if(credentials != null) {
                credentialsProvider.setCredentials(authScope, credentials);
            }
        }
    }
    
    /**
     * Get all the request headers for the <code>HttpMethod</code>
     *
     * @param method
     *            <code>HttpMethod</code> which represents the request
     * @return the headers as a string
     */
    protected String getConnectionHeaders(HttpRequest method) {
        // Get all the request headers
        StringBuilder hdrs = new StringBuilder(100);
        Header[] requestHeaders = method.getAllHeaders();
        for(int i = 0; i < requestHeaders.length; i++) {
            // Exclude the COOKIE header, since cookie is reported separately in the sample
            if(!UPMPConstant.HEADER_COOKIE.equalsIgnoreCase(requestHeaders[i].getName())) {
                hdrs.append(requestHeaders[i].getName());
                hdrs.append(": "); // $NON-NLS-1$
                hdrs.append(requestHeaders[i].getValue());
                hdrs.append("\n"); // $NON-NLS-1$
            }
        }

        return hdrs.toString();
    }
    
    /**
     * Gets the ResponseHeaders
     *
     * @param response
     *            containing the headers
     * @return string containing the headers, one per line
     */
    protected String getResponseHeaders(HttpResponse response) {
        StringBuilder headerBuf = new StringBuilder();
        Header[] rh = response.getAllHeaders();
        headerBuf.append(response.getStatusLine());// header[0] is not the status line...
        headerBuf.append("\n"); // $NON-NLS-1$

        for (int i = 0; i < rh.length; i++) {
            headerBuf.append(rh[i].getName());
            headerBuf.append(": "); // $NON-NLS-1$
            headerBuf.append(rh[i].getValue());
            headerBuf.append("\n"); // $NON-NLS-1$
        }
        return headerBuf.toString();
    }

    /**
     * Extracts all the required cookies for that particular URL request and
     * sets them in the <code>HttpMethod</code> passed in.
     *
     * @param request <code>HttpRequest</code> for the request
     * @param url <code>URL</code> of the request
     * @param cookieManager the <code>CookieManager</code> containing all the cookies
     * @return a String containing the cookie details (for the response)
     * May be null
     */
    protected String setConnectionCookie(HttpRequest request, URL url, CookieManager cookieManager) {
        String cookieHeader = null;
        if (cookieManager != null) {
            cookieHeader = cookieManager.getCookieHeaderForURL(url);
            if (cookieHeader != null) {
                request.setHeader(UPMPConstant.HEADER_COOKIE, cookieHeader);
            }
        }
        return cookieHeader;
    }
    
    /**
     * 
     * @return the value of {@link #getContentEncoding()}; forced to null if empty
     */
    protected String getContentEncodingOrNull() {
        return getContentEncoding(null);
    }

    /**
     * @param dflt the default to be used
     * @return the value of {@link #getContentEncoding()}; default if null or empty
     */
    protected String getContentEncoding(String dflt) {
        String ce = getContentEncoding();
        if (isNullOrEmptyTrimmed(ce)) {
            return dflt;
        } else {
            return ce;
        }
    }
    
    /**
     * If contentEncoding is not set by user, then Platform encoding will be used to convert to String
     * @param putParams {@link HttpParams}
     * @return String charset
     */
    protected String getCharsetWithDefault(HttpParams putParams) {
        String charset =(String) putParams.getParameter(CoreProtocolPNames.HTTP_CONTENT_CHARSET);
        if(StringUtils.isEmpty(charset)) {
            charset = Charset.defaultCharset().name();
        }
        return charset;
    }

    protected void saveConnectionCookies(HttpResponse method, URL u, CookieManager cookieManager) {
        if (cookieManager != null) {
            Header[] hdrs = method.getHeaders(UPMPConstant.HEADER_SET_COOKIE);
            for (Header hdr : hdrs) {
                cookieManager.addCookieFromHeader(hdr.getValue(),u);
            }
        }
    }
    
    public void threadFinished() {
        log.debug("Thread Finished");
        closeThreadLocalConnections();
    }

    public boolean interrupt() {
        HttpUriRequest request = currentRequest;
        if (request != null) {
            currentRequest = null; // don't try twice
            try {
                request.abort();
            } catch (UnsupportedOperationException e) {
                log.warn("Could not abort pending request", e);
            }
        }
        return request != null;
    }
    
    /**
     * Set any default request headers to include
     *
     * @param request the HttpRequest to be used
     */
    protected void setDefaultRequestHeaders(HttpRequest request) {
     // Method left empty here, but allows subclasses to override
    }
    
    protected void setupRequest(URL url, HttpRequestBase httpRequest, UPMPSampleResult res)
            throws IOException {

    	    HttpParams requestParams = httpRequest.getParams();
    	    
    	    // Set up the local address if one exists
    	    final String ipSource = getIpSource();
    	    if (ipSource.length() > 0) {// Use special field ip source address (for pseudo 'ip spoofing')
    	        InetAddress inetAddr = InetAddress.getByName(ipSource);
    	        requestParams.setParameter(ConnRoutePNames.LOCAL_ADDRESS, inetAddr);
    	    } else if (localAddress != null){
    	        requestParams.setParameter(ConnRoutePNames.LOCAL_ADDRESS, localAddress);
    	    } else { // reset in case was set previously
    	        requestParams.removeParameter(ConnRoutePNames.LOCAL_ADDRESS);
    	    }
    	
    	    int rto = getResponseTimeout();
    	    if (rto > 0){
    	        requestParams.setIntParameter(CoreConnectionPNames.SO_TIMEOUT, rto);
    	    }
    	
    	    int cto = getConnectTimeout();
    	    if (cto > 0){
    	        requestParams.setIntParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, cto);
    	    }
    	
    	    requestParams.setBooleanParameter(ClientPNames.HANDLE_REDIRECTS, getAutoRedirects());
    	    
    	    // a well-behaved browser is supposed to send 'Connection: close'
    	    // with the last request to an HTTP server. Instead, most browsers
    	    // leave it to the server to close the connection after their
    	    // timeout period. Leave it to the JMeter user to decide.
    	    if (getUseKeepAlive()) {
    	        httpRequest.setHeader(UPMPConstant.HEADER_CONNECTION, UPMPConstant.KEEP_ALIVE);
    	    } else {
    	        httpRequest.setHeader(UPMPConstant.HEADER_CONNECTION, UPMPConstant.CONNECTION_CLOSE);
    	    }
    	
    	    setConnectionHeaders(httpRequest, url, getHeaderManager(), getCacheManager());
    	
    	    String cookies = setConnectionCookie(httpRequest, url, getCookieManager());
    	
    	    if (res != null) {
    	        res.setCookies(cookies);
    	    }

        }
    
}
