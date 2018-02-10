package com.motikan2010.util;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

public class RequestResponseUtils {

    private IBurpExtenderCallbacks iBurpExtenderCallbacks;
    private IExtensionHelpers iExtensionHelpers;

    private static final String NEW_LINE = System.lineSeparator();

    public RequestResponseUtils(IBurpExtenderCallbacks callbacks) {
        this.iBurpExtenderCallbacks = callbacks;
        this.iExtensionHelpers = callbacks.getHelpers();
    }


    public String getRequestFull(IHttpRequestResponse requestResponse) {
        IRequestInfo iRequestInfo = this.iExtensionHelpers.analyzeRequest(requestResponse.getRequest());

        StringBuilder stringBuilder = new StringBuilder();
        // Get Request Headers
        for (String header : iRequestInfo.getHeaders()) {
            stringBuilder.append(header + NEW_LINE);
        }

        // Get Request body
        String requestBody = getRaw(iRequestInfo, requestResponse.getRequest());
        if (requestBody.length() > 0) {
            stringBuilder.append(NEW_LINE + requestBody);
        }
        return stringBuilder.toString();
    }

    /**
     *
     * @param iRequestInfo
     * @param requestBytes
     * @return
     */
    private String getRaw(IRequestInfo iRequestInfo, byte[] requestBytes) {
        String request = null;
        try {
            request = new String(requestBytes, "UTF-8");
            request = request.substring(iRequestInfo.getBodyOffset());
        } catch (UnsupportedEncodingException e) {
            System.out.println("Error converting string");
        }
        return request;
    }

    /**
     *
     *
     * @param requestResponse IHttpRequestResponse.getResponse()
     * @return
     */
    public String getResponseFull(IHttpRequestResponse requestResponse) {
        return new String(requestResponse.getResponse(), StandardCharsets.UTF_8);
    }

    public String getNewLine() {
        return NEW_LINE;
    }
}
