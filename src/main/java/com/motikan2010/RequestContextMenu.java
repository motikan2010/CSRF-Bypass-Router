package com.motikan2010;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;


public class RequestContextMenu implements MouseListener {

    private IBurpExtenderCallbacks iBurpExtenderCallbacks;
    private IExtensionHelpers iExtensionHelpers;
    private IHttpRequestResponse[] iHttpRequestResponseArray;
    private RequestFlowTab requestFlowTab;

    public RequestContextMenu(IBurpExtenderCallbacks callbacks, IHttpRequestResponse[] httpRequestResponseArray, RequestFlowTab requestFlowTab) {
        this.iBurpExtenderCallbacks = callbacks;
        this.iExtensionHelpers = callbacks.getHelpers();
        this.iHttpRequestResponseArray = httpRequestResponseArray;
        this.requestFlowTab = requestFlowTab;
    }

    @Override
    public void mouseReleased(MouseEvent e) {
        for (IHttpRequestResponse iHttpRequestResponse : iHttpRequestResponseArray) {
            this.requestFlowTab.saveRequest(this.iExtensionHelpers.analyzeRequest(iHttpRequestResponse));
        }
    }

    @Override
    public void mouseClicked(MouseEvent e) {
    }

    @Override
    public void mousePressed(MouseEvent e) {
    }

    @Override
    public void mouseEntered(MouseEvent e) {
    }

    @Override
    public void mouseExited(MouseEvent e) {
    }
}
