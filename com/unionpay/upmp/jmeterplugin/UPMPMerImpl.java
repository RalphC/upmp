package com.unionpay.upmp.jmeterplugin;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;

import org.apache.http.Header;
import org.apache.http.HttpConnectionMetrics;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;
import org.apache.http.params.CoreProtocolPNames;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.ExecutionContext;
import org.apache.http.protocol.HttpContext;
import org.apache.jmeter.protocol.http.control.CacheManager;
import org.apache.jmeter.protocol.http.util.EncoderCache;
import org.apache.jmeter.protocol.http.util.HTTPArgument;
import org.apache.jmeter.testelement.property.PropertyIterator;
import org.apache.jorphan.logging.LoggingManager;
import org.apache.log.Logger;

import com.unionpay.upmp.util.SecurityUtil;
import com.unionpay.upmp.util.UPMPConstant;

public class UPMPMerImpl extends UPMPAbstractImpl {

    private static final Logger log = LoggingManager.getLoggerForClass();

    protected UPMPMerImpl(UPMPSamplerBase testElement) {
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
            } else {
                throw new IllegalArgumentException("Unexpected method: "+method);
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
                res.setResponseData(readResponse(res, instream, (int) entity.getContentLength()));
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
            if (res.isRedirect()) {
                final Header headerLocation = httpResponse.getLastHeader(UPMPConstant.HEADER_LOCATION);
                if (headerLocation == null) { // HTTP protocol violation, but avoids NPE
                    throw new IllegalArgumentException("Missing location header");
                }
                res.setRedirectLocation(headerLocation.getValue());
            }

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

            // If we redirected automatically, the URL may have changed
            if (getAutoRedirects()){
                HttpUriRequest req = (HttpUriRequest) localContext.getAttribute(ExecutionContext.HTTP_REQUEST);
                HttpHost target = (HttpHost) localContext.getAttribute(ExecutionContext.HTTP_TARGET_HOST);
                URI redirectURI = req.getURI();
                if (redirectURI.isAbsolute()){
                    res.setURL(redirectURI.toURL());
                } else {
                    res.setURL(new URL(new URL(target.toURI()),redirectURI.toString()));
                }
            }

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
        } finally {
            currentRequest = null;
        }
        return res;
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
		
		String secureKey = req.get("securekey");
		req.remove("securekey");
	    Map<String, String> filteredReq = SecurityUtil.paraFilter(req);
	    String signature = SecurityUtil.buildSignature(filteredReq, secureKey);
	    filteredReq.put("signature", signature);
	    filteredReq.put("signMethod", UPMPConstant.upmp_sign_method);
		String request = SecurityUtil.createLinkString(UPMPConstant.upmp_charset, filteredReq, false, true);
		
		StringEntity entity = new StringEntity(request);
		post.setEntity(entity);
		
		postedBody.append(request);     
        return postedBody.toString();
    }

    // TODO merge put and post methods as far as possible.
    // e.g. post checks for multipart form/files, and if not, invokes sendData(HttpEntityEnclosingRequestBase)



}
