package com.unionpay.upmp.jmeterplugin;

import java.net.HttpURLConnection;
import java.net.URL;

import org.apache.jmeter.protocol.http.util.HTTPConstants;
import org.apache.jmeter.samplers.SampleResult;

public class UPMPSampleResult extends SampleResult {
    private static final long serialVersionUID = 1L;

    private String cookies = ""; // never null

    private String method;
    
    private String type;

    /**
     * The raw value of the Location: header; may be null.
     * This is supposed to be an absolute URL:
     * <a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.30">RFC2616 sec14.30</a>
     * but is often relative.
     */
    private String redirectLocation;

    private String queryString = ""; // never null

    private static final String HTTP_NO_CONTENT_CODE = Integer.toString(HttpURLConnection.HTTP_NO_CONTENT);
    private static final String HTTP_NO_CONTENT_MSG = "No Content"; // $NON-NLS-1$

    public UPMPSampleResult() {
        super();
    }

    public UPMPSampleResult(long elapsed) {
        super(elapsed, true);
    }

    /**
     * Construct a 'parent' result for an already-existing result, essentially
     * cloning it
     *
     * @param res
     *            existing sample result
     */
    public UPMPSampleResult(UPMPSampleResult res) {
        super(res);
        method=res.method;
        cookies=res.cookies;
        queryString=res.queryString;
        redirectLocation=res.redirectLocation;
    }

    public void setUPMPMethod(String method) {
        this.method = method;
    }

    public String getUPMPMethod() {
        return method;
    }

    public void setRedirectLocation(String redirectLocation) {
        this.redirectLocation = redirectLocation;
    }

    public String getRedirectLocation() {
        return redirectLocation;
    }

    /**
     * Determine whether this result is a redirect.
     *
     * @return true iif res is an HTTP redirect response
     */
    public boolean isRedirect() {
        /*
         * Don't redirect the following:
         * 304 = Not Modified
         * 305 = Use Proxy
         * 306 = (Unused)
         */
        final String[] REDIRECT_CODES = { "301", "302", "303" };
        String code = getResponseCode();
        for (int i = 0; i < REDIRECT_CODES.length; i++) {
            if (REDIRECT_CODES[i].equals(code)) {
                return true;
            }
        }
        // http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
        // If the 307 status code is received in response to a request other than GET or HEAD, 
        // the user agent MUST NOT automatically redirect the request unless it can be confirmed by the user,
        // since this might change the conditions under which the request was issued.
        // See Bug 54119
        if ("307".equals(code) && 
                (HTTPConstants.GET.equals(getUPMPMethod()) || HTTPConstants.HEAD.equals(getUPMPMethod()))) {
            return true;
        }
        return false;
    }

    /**
     * Overrides version in Sampler data to provide more details
     * <p>
     * {@inheritDoc}
     */
    @Override
    public String getSamplerData() {
        StringBuilder sb = new StringBuilder();
        sb.append(method);
        URL u = super.getURL();
        if (u != null) {
            sb.append(' ');
            sb.append(u.toString());
            sb.append("\n");
            // Include request body if it is a post or put or patch
            if (HTTPConstants.POST.equals(method) || HTTPConstants.PUT.equals(method) || HTTPConstants.PATCH.equals(method)) {
                sb.append("\n"+method+" data:\n");
                sb.append(queryString);
                sb.append("\n");
            }
            if (cookies.length()>0){
                sb.append("\nCookie Data:\n");
                sb.append(cookies);
            } else {
                sb.append("\n[no cookies]");
            }
            sb.append("\n");
        }
        final String sampData = super.getSamplerData();
        if (sampData != null){
            sb.append(sampData);
        }
        return sb.toString();
    }

    /**
     * @return cookies as a string
     */
    public String getCookies() {
        return cookies;
    }

    /**
     * @param string
     *            representing the cookies
     */
    public void setCookies(String string) {
        if (string == null) {
            cookies="";// $NON-NLS-1$
        } else {
            cookies = string;
        }
    }

    /**
     * Fetch the query string
     *
     * @return the query string
     */
    public String getQueryString() {
        return queryString;
    }

    /**
     * Save the query string
     *
     * @param string
     *            the query string
     */
    public void setQueryString(String string) {
        if (string == null ) {
            queryString="";// $NON-NLS-1$
        } else {
            queryString = string;
        }
    }
    /**
     * Overrides the method from SampleResult - so the encoding can be extracted from
     * the Meta content-type if necessary.
     *
     * Updates the dataEncoding field if the content-type is found.
     *
     * @return the dataEncoding value as a String
     */
    @Override
    public String getDataEncodingWithDefault() {
        if (getDataEncodingNoDefault() == null && getContentType().startsWith("text/html")){ // $NON-NLS-1$
            byte[] bytes=getResponseData();
            // get the start of the file
            // TODO - charset?
            String prefix = new String(bytes,0,Math.min(bytes.length, 2000)).toLowerCase(java.util.Locale.ENGLISH);
            // Extract the content-type if present
            final String METATAG = "<meta http-equiv=\"content-type\" content=\""; // $NON-NLS-1$
            int tagstart=prefix.indexOf(METATAG);
            if (tagstart!=-1){
                tagstart += METATAG.length();
                int tagend = prefix.indexOf('\"', tagstart); // $NON-NLS-1$
                if (tagend!=-1){
                    // TODO use fixed charset:
                    final String ct = new String(bytes,tagstart,tagend-tagstart); // TODO - charset?
                    setEncodingAndType(ct);// Update the dataEncoding
                }
            }
        }
        return super.getDataEncodingWithDefault(DEFAULT_HTTP_ENCODING);
    }

    public void setResponseNoContent(){
        setResponseCode(HTTP_NO_CONTENT_CODE);
        setResponseMessage(HTTP_NO_CONTENT_MSG);
    }
    
    public void setUPMPType(String type) {
        this.type = type;
    }

    public String getUPMPType() {
        return type;
    }
    
}
