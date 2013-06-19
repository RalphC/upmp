package com.unionpay.upmp.jmeterplugin;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.Header;
import org.apache.http.HttpConnection;
import org.apache.http.HttpConnectionMetrics;
import org.apache.http.HttpEntity;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.StatusLine;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.NTCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.client.params.CookiePolicy;
import org.apache.http.client.protocol.ResponseContentEncoding;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.AbstractHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.CoreConnectionPNames;
import org.apache.http.params.CoreProtocolPNames;
import org.apache.http.params.DefaultedHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.ExecutionContext;
import org.apache.http.protocol.HttpContext;
import org.apache.jmeter.protocol.http.control.AuthManager;
import org.apache.jmeter.protocol.http.control.Authorization;
import org.apache.jmeter.protocol.http.control.CacheManager;
import org.apache.jmeter.protocol.http.control.CookieManager;
import org.apache.jmeter.protocol.http.control.HeaderManager;
import org.apache.jmeter.protocol.http.sampler.HttpClientDefaultParameters;
import org.apache.jmeter.protocol.http.util.EncoderCache;
import org.apache.jmeter.protocol.http.util.HC4TrustAllSSLSocketFactory;
import org.apache.jmeter.protocol.http.util.HTTPArgument;
import org.apache.jmeter.protocol.http.util.SlowHC4SSLSocketFactory;
import org.apache.jmeter.protocol.http.util.SlowHC4SocketFactory;
import org.apache.jmeter.testelement.property.CollectionProperty;
import org.apache.jmeter.testelement.property.PropertyIterator;
import org.apache.jmeter.util.JMeterUtils;
import org.apache.jorphan.logging.LoggingManager;
import org.apache.log.Logger;

import com.unionpay.upmp.util.BytesUtil;
import com.unionpay.upmp.util.DESUtil;
import com.unionpay.upmp.util.RSAUtil;
import com.unionpay.upmp.util.UPMPConstant;

public class UPMPMobileImpl extends UPMPAbstractImpl {

	private static String currentKey = null;
	
    private static final Logger log = LoggingManager.getLoggerForClass();

    /** retry count to be used (default 1); 0 = disable retries */
    private static final int RETRY_COUNT = JMeterUtils.getPropDefault("httpclient4.retrycount", 1);

    private static final String CONTEXT_METRICS = "jmeter_metrics"; // TODO hack, to be removed later

    private static final HttpResponseInterceptor METRICS_SAVER = new HttpResponseInterceptor(){
        @Override
        public void process(HttpResponse response, HttpContext context)
                throws HttpException, IOException {
            HttpConnection conn = (HttpConnection) context.getAttribute(ExecutionContext.HTTP_CONNECTION);
            HttpConnectionMetrics metrics = conn.getMetrics();
            context.setAttribute(CONTEXT_METRICS, metrics);
        }
    };
    private static final HttpRequestInterceptor METRICS_RESETTER = new HttpRequestInterceptor() {
		@Override
        public void process(HttpRequest request, HttpContext context)
				throws HttpException, IOException {
            HttpConnection conn = (HttpConnection) context.getAttribute(ExecutionContext.HTTP_CONNECTION);
			HttpConnectionMetrics metrics = conn.getMetrics();
			metrics.reset();
		}
	};

    private static final ThreadLocal<Map<HttpClientKey, HttpClient>> HTTPCLIENTS = 
        new ThreadLocal<Map<HttpClientKey, HttpClient>>(){
        @Override
        protected Map<HttpClientKey, HttpClient> initialValue() {
            return new HashMap<HttpClientKey, HttpClient>();
        }
    };

    // Scheme used for slow HTTP sockets. Cannot be set as a default, because must be set on an HttpClient instance.
    private static final Scheme SLOW_HTTP;
    
    // We always want to override the HTTPS scheme, because we want to trust all certificates and hosts
    private static final Scheme HTTPS_SCHEME;

    /*
     * Create a set of default parameters from the ones initially created.
     * This allows the defaults to be overridden if necessary from the properties file.
     */
    private static final HttpParams DEFAULT_HTTP_PARAMS;
    
    static {
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

    private volatile HttpUriRequest currentRequest; // Accessed from multiple threads

    protected UPMPMobileImpl(UPMPSamplerBase testElement) {
        super(testElement);
    }

    @Override
    protected UPMPSampleResult sample(URL url, String method,
            boolean areFollowingRedirect, int frameDepth) {

    	UPMPSampleResult res = new UPMPSampleResult();
        res.setMonitor(isMonitor());

        res.setSampleLabel(url.toString()); // May be replaced later
        res.setUPMPMethod(method);
        res.setURL(url);

        HttpClient httpClient = setupClient(url);
        
        HttpRequestBase httpRequest = null;
        try {
            URI uri = url.toURI();
            if (method.equals(UPMPConstant.POST)) {
                httpRequest = new HttpPost(uri);
            } else if (method.equals(UPMPConstant.GET)) {
                httpRequest = new HttpGet(uri);
            } else {
                throw new IllegalArgumentException("Unsupported method: "+method);
            }
            setupRequest(url, httpRequest, res); // can throw IOException
        } catch (Exception e) {
            res.sampleStart();
            res.sampleEnd();
            errorResult(e, res);
            return res;
        }

        HttpContext localContext = new BasicHttpContext();
        
        res.sampleStart();

        final CacheManager cacheManager = getCacheManager();
        if (cacheManager != null && UPMPConstant.GET.equalsIgnoreCase(method)) {
           if (cacheManager.inCache(url)) {
               res.sampleEnd();
               res.setResponseNoContent();
               res.setSuccessful(true);
               return res;
           }
        }

        try {
            currentRequest = httpRequest;
            // Handle the various methods
            if (method.equals(UPMPConstant.POST)) {
                String postBody = sendPostData((HttpPost)httpRequest);
                res.setQueryString(postBody);
            }
            HttpResponse httpResponse = httpClient.execute(httpRequest, localContext); // perform the sample

            // Needs to be done after execute to pick up all the headers
            res.setRequestHeaders(getConnectionHeaders((HttpRequest) localContext.getAttribute(ExecutionContext.HTTP_REQUEST)));

            Header contentType = httpResponse.getLastHeader(UPMPConstant.HEADER_CONTENT_TYPE);
            if (contentType != null){
                String ct = contentType.getValue();
                res.setContentType(ct);
                res.setEncodingAndType(ct);                    
            }
            HttpEntity entity = httpResponse.getEntity();
            if (entity != null) {
                InputStream instream = entity.getContent();
                
                // Decode using currentKey
                byte[] respBytes = readResponse(res, instream, (int) entity.getContentLength());
                String respString = new String(respBytes,"UTF-8");
                byte[] orginResponse = DESUtil.ecbDecrypt(BytesUtil.hexToBytes(currentKey), BytesUtil.hexToBytes(respString), 2);
                res.setResponseData(orginResponse);
            }
            
            res.sampleEnd(); // Done with the sampling proper.
            currentRequest = null;

            
            // Now collect the results into the HTTPSampleResult:
            StatusLine statusLine = httpResponse.getStatusLine();
            int statusCode = statusLine.getStatusCode();
            res.setResponseCode(Integer.toString(statusCode));
            res.setResponseMessage(statusLine.getReasonPhrase());
            res.setSuccessful(isSuccessCode(statusCode));

            res.setResponseHeaders(getResponseHeaders(httpResponse));
//            if (res.isRedirect()) {
//                final Header headerLocation = httpResponse.getLastHeader(UPMPConstant.HEADER_LOCATION);
//                if (headerLocation == null) { // HTTP protocol violation, but avoids NPE
//                    throw new IllegalArgumentException("Missing location header");
//                }
//                res.setRedirectLocation(headerLocation.getValue());
//            }

            // record some sizes to allow HTTPSampleResult.getBytes() with different options
            HttpConnectionMetrics  metrics = (HttpConnectionMetrics) localContext.getAttribute(CONTEXT_METRICS);
            long headerBytes = 
                res.getResponseHeaders().length()   // condensed length (without \r)
              + httpResponse.getAllHeaders().length // Add \r for each header
              + 1 // Add \r for initial header
              + 2; // final \r\n before data
            long totalBytes = metrics.getReceivedBytesCount();
            res.setHeadersSize((int) headerBytes);
            res.setBodySize((int)(totalBytes - headerBytes));
            if (log.isDebugEnabled()) {
                log.debug("ResponseHeadersSize=" + res.getHeadersSize() + " Content-Length=" + res.getBodySize()
                        + " Total=" + (res.getHeadersSize() + res.getBodySize()));
            }

//            // If we redirected automatically, the URL may have changed
//            if (getAutoRedirects()){
//                HttpUriRequest req = (HttpUriRequest) localContext.getAttribute(ExecutionContext.HTTP_REQUEST);
//                HttpHost target = (HttpHost) localContext.getAttribute(ExecutionContext.HTTP_TARGET_HOST);
//                URI redirectURI = req.getURI();
//                if (redirectURI.isAbsolute()){
//                    res.setURL(redirectURI.toURL());
//                } else {
//                    res.setURL(new URL(new URL(target.toURI()),redirectURI.toString()));
//                }
//            }

            // Store any cookies received in the cookie manager:
            saveConnectionCookies(httpResponse, res.getURL(), getCookieManager());

            // Save cache information
            if (cacheManager != null){
                cacheManager.saveDetails(httpResponse, res);
            }

            // Follow redirects and download page resources if appropriate:
            res = resultProcessing(areFollowingRedirect, frameDepth, res);

        } catch (IOException e) {
            res.sampleEnd();
           // pick up headers if failed to execute the request
            res.setRequestHeaders(getConnectionHeaders((HttpRequest) localContext.getAttribute(ExecutionContext.HTTP_REQUEST)));
            errorResult(e, res);
            return res;
        } catch (RuntimeException e) {
            res.sampleEnd();
            errorResult(e, res);
            return res;
        } catch (GeneralSecurityException e) {
            res.sampleEnd();
            errorResult(e, res);
		} finally {
            currentRequest = null;
        }
        return res;
    }

    /**
     * Holder class for all fields that define an HttpClient instance;
     * used as the key to the ThreadLocal map of HttpClient instances.
     */
    private static final class HttpClientKey {

        private final String target; // protocol://[user:pass@]host:[port]
        private final boolean hasProxy;
        private final String proxyHost;
        private final int proxyPort;
        private final String proxyUser;
        private final String proxyPass;
        
        private final int hashCode; // Always create hash because we will always need it

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
        
        private int getHash() {
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
        private int getHash(String s) {
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

    private HttpClient setupClient(URL url) {

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

    private void setupRequest(URL url, HttpRequestBase httpRequest, UPMPSampleResult res)
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

    
    /**
     * Set any default request headers to include
     *
     * @param request the HttpRequest to be used
     */
    protected void setDefaultRequestHeaders(HttpRequest request) {
     // Method left empty here, but allows subclasses to override
    }

    /**
     * Gets the ResponseHeaders
     *
     * @param response
     *            containing the headers
     * @return string containing the headers, one per line
     */
    private String getResponseHeaders(HttpResponse response) {
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
    private String setConnectionCookie(HttpRequest request, URL url, CookieManager cookieManager) {
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
    private void setConnectionHeaders(HttpRequestBase request, URL url, HeaderManager headerManager, CacheManager cacheManager) {
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
     * Get all the request headers for the <code>HttpMethod</code>
     *
     * @param method
     *            <code>HttpMethod</code> which represents the request
     * @return the headers as a string
     */
    private String getConnectionHeaders(HttpRequest method) {
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
     * Setup credentials for url AuthScope but keeps Proxy AuthScope credentials
     * @param client HttpClient
     * @param url URL
     * @param authManager {@link AuthManager}
     * @param key key
     */
    private void setConnectionAuthorization(HttpClient client, URL url, AuthManager authManager, HttpClientKey key) {
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

    // TODO needs cleaning up
    private String sendPostData(HttpPost post)  throws IOException {
        // Buffer to hold the post body, except file content
        StringBuilder postedBody = new StringBuilder(2048);

        final String contentEncoding = getContentEncodingOrNull();
        final boolean haveContentEncoding = contentEncoding != null;

		// Check if the header manager had a content type header
		// This allows the user to specify his own content-type for a POST request
		Header contentTypeHeader = post.getFirstHeader(UPMPConstant.HEADER_CONTENT_TYPE);
		boolean hasContentTypeHeader = contentTypeHeader != null && contentTypeHeader.getValue() != null && contentTypeHeader.getValue().length() > 0;

		if(haveContentEncoding) {
			post.getParams().setParameter(CoreProtocolPNames.HTTP_CONTENT_CHARSET, contentEncoding);
		}

		if(!hasContentTypeHeader) {
			post.setHeader(UPMPConstant.HEADER_CONTENT_TYPE, UPMPConstant.APPLICATION_X_WWW_FORM_URLENCODED);
		}
		// Add the parameters
		PropertyIterator args = getArguments().iterator();
		Map<String, String> req = new HashMap<String, String>();
		String urlContentEncoding = contentEncoding;
		if(urlContentEncoding == null || urlContentEncoding.length() == 0) {
			// Use the default encoding for urls
			urlContentEncoding = EncoderCache.URL_ARGUMENT_ENCODING;
		}
		while (args.hasNext()) {
			HTTPArgument arg = (HTTPArgument) args.next().getObjectValue();
			// The HTTPClient always urlencodes both name and value,
			// so if the argument is already encoded, we have to decode
			// it before adding it to the post request
			String parameterName = arg.getName();
			if (arg.isSkippable(parameterName)){
				continue;
			}
			String parameterValue = arg.getValue();
			if(!arg.isAlwaysEncoded()) {
				// The value is already encoded by the user
				// Must decode the value now, so that when the
				// httpclient encodes it, we end up with the same value
				// as the user had entered.
				parameterName = URLDecoder.decode(parameterName, urlContentEncoding);
				parameterValue = URLDecoder.decode(parameterValue, urlContentEncoding);
			}
			// Add the parameter, httpclient will urlencode it
			req.put(parameterName, parameterValue);
		}
		
		String type = req.get(UPMPConstant.upmp_mobile_message_type);
		if (type.equals("init")) {
			byte[] key = DESUtil.genKey(req.get("initkey"));
			currentKey = BytesUtil.bytesToHex(key);
			PublicKey pubKey = RSAUtil.generateRSAPublicKey(UPMPConstant.modulus, UPMPConstant.publicExponent);
			byte[] keyBytes = RSAUtil.encrypt(key, pubKey);
			String tmpKey = BytesUtil.bytesToHex(keyBytes);
			post.setHeader("secret", tmpKey);
			req.remove("initkey");
			req.put("initkey", currentKey);
		} else {
			currentKey = req.get("secret");
			post.setHeader("sid", req.get("sid"));
		}
		String request = UPMPMobileMessageBuilder.BuildMessage(req, type);
		
		StringEntity entity = new StringEntity(request, "UTF-8");
		post.setEntity(entity);
		
		postedBody.append(request);     
        return postedBody.toString();
    }

    // TODO merge put and post methods as far as possible.
    // e.g. post checks for multipart form/files, and if not, invokes sendData(HttpEntityEnclosingRequestBase)


    /**
     * 
     * @return the value of {@link #getContentEncoding()}; forced to null if empty
     */
    private String getContentEncodingOrNull() {
        return getContentEncoding(null);
    }

    /**
     * @param dflt the default to be used
     * @return the value of {@link #getContentEncoding()}; default if null or empty
     */
    private String getContentEncoding(String dflt) {
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

    private void saveConnectionCookies(HttpResponse method, URL u, CookieManager cookieManager) {
        if (cookieManager != null) {
            Header[] hdrs = method.getHeaders(UPMPConstant.HEADER_SET_COOKIE);
            for (Header hdr : hdrs) {
                cookieManager.addCookieFromHeader(hdr.getValue(),u);
            }
        }
    }

    @Override
    public void threadFinished() {
        log.debug("Thread Finished");
        closeThreadLocalConnections();
    }

    /**
     * 
     */
    private void closeThreadLocalConnections() {
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

    @Override
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
    
    /** {@inheritDoc} */
    @Override
    protected void notifySSLContextWasReset() {
        log.debug("closeThreadLocalConnections called");
        closeThreadLocalConnections();
    }
}
