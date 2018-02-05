package com.motikan2010;

import burp.*;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.List;

public class RequestFlowTab extends JPanel {

    private static IBurpExtenderCallbacks iBurpExtenderCallbacks;
    private static IExtensionHelpers iExtensionHelpers;

    private static final int PANEL_X = 10;
    private static final int PANEL_Y = 10;

    private static final int PANEL_WIDTH = 500;
    private static final int PANEL_HEIGHT = 110;

    private static final String NEW_LINE = System.lineSeparator();
    private List<IRequestInfo> iRequestInfoList;
    private List<IHttpRequestResponse> iHttpRequestResponseList;
    private TextArea requestResponseTextArea;

    private static RequestFlowTab panel;

    private JTable jTable;
    private RequestTable requestTable;
    private JScrollPane requestScrollPane;
    private TextArea requestTextArea;

    public static RequestFlowTab getInstance(IBurpExtenderCallbacks callbacks) {
        iBurpExtenderCallbacks = callbacks;
        iExtensionHelpers = callbacks.getHelpers();
        if (panel == null) {
            panel = new RequestFlowTab();
        }
        return panel;
    }

    /**
     *
     */
    public void render() {
        setLayout(null);
        iRequestInfoList = new LinkedList<>();
        iHttpRequestResponseList = new LinkedList<>();

        /*
            [Label] Request Flow
         */
        Label requestTableLabel = new Label("Request Flow");
        requestTableLabel.setBounds(PANEL_X, PANEL_Y, 145, 23);
        requestTableLabel.setForeground(new Color(229, 137, 0));
        requestTableLabel.setFont(new Font("Dialog", Font.BOLD, 15));

        /*
            [Table]
         */
        requestTable = new RequestTable();
        jTable = new JTable(requestTable);

        // Click table row
        jTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                selectRequest(jTable.getSelectedRow());
            }
        });

        // No Column
        jTable.getColumnModel().getColumn(RequestTable.NO_COLUMN_INDEX).setWidth(20);
        jTable.getColumnModel().getColumn(RequestTable.NO_COLUMN_INDEX).setMaxWidth(30);

        // Enable Column
        jTable.getColumnModel().getColumn(RequestTable.ENABLED_COLUMN_INDEX).setWidth(20);
        jTable.getColumnModel().getColumn(RequestTable.ENABLED_COLUMN_INDEX).setMaxWidth(20);
        jTable.getColumnModel().getColumn(RequestTable.ENABLED_COLUMN_INDEX).setResizable(false);

        // Host Column
        jTable.getColumnModel().getColumn(RequestTable.HOST_COLUMN_INDEX).setPreferredWidth(150);
        jTable.getColumnModel().getColumn(RequestTable.HOST_COLUMN_INDEX).setMinWidth(100);
        jTable.getColumnModel().getColumn(RequestTable.HOST_COLUMN_INDEX).setMaxWidth(250);

        // Column
        jTable.getColumnModel().getColumn(RequestTable.METHOD_COLUMN_INDEX).setMaxWidth(50);
        jTable.getColumnModel().getColumn(RequestTable.METHOD_COLUMN_INDEX).setResizable(false);

        // Column
        jTable.getColumnModel().getColumn(RequestTable.URL_COLUMN_INDEX).setPreferredWidth(150);

        requestScrollPane = new JScrollPane(jTable);
        requestScrollPane.setLocation(PANEL_X, PANEL_Y + 25);
        requestScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        requestScrollPane.setSize(PANEL_WIDTH, PANEL_HEIGHT + 25);

        /*
            [Label] Request
         */
        Label requestLabel = new Label("Request");
        requestLabel.setBounds(PANEL_X, 175, 145, 23);
        requestLabel.setForeground(new Color(229, 137, 0));
        requestLabel.setFont(new Font("Dialog", Font.BOLD, 15));

        /*
            [Text Area]
         */
        requestTextArea = new TextArea();
        requestTextArea.setSize(PANEL_WIDTH, 400);
        requestTextArea.setLocation(PANEL_X, 200);

        /*
            [Label] Request & Response
         */
        Label requestResponseLabel = new Label("Request & Response");
        requestResponseLabel.setBounds(PANEL_X + 500, PANEL_Y, 200, 23);
        requestResponseLabel.setForeground(new Color(229, 137, 0));
        requestResponseLabel.setFont(new Font("Dialog", Font.BOLD, 15));

        /*
            [Button] Send
         */
        JButton sendButton = new JButton("Send");
        sendButton.setBounds(PANEL_X + 700, PANEL_Y - 5, 80, 30);
        sendButton.addActionListener(e -> {
            Runnable runner = () -> {
                sendRequest();
            };
            runner.run();
        });

        /*
            [Text Area]
         */
        requestResponseTextArea = new TextArea();
        requestResponseTextArea.setSize(PANEL_WIDTH, 400);
        requestResponseTextArea.setLocation(PANEL_X + 500, PANEL_Y + 25);

        /*
            [Button] Clear
         */
        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> {

        });

        add(requestTableLabel);
        add(requestScrollPane);
        add(requestLabel);
        add(requestTextArea);
        add(requestResponseLabel);
        add(sendButton);
        add(requestResponseTextArea);
        add(clearButton);
    }

    /**
     *
     * @param rowNum
     */
    public void selectRequest(int rowNum) {
        IRequestInfo iRequestInfo = iRequestInfoList.get(rowNum);
        IHttpRequestResponse iHttpRequestResponse = iHttpRequestResponseList.get(rowNum);

        StringBuilder stringBuilder = new StringBuilder();
        // Get Request Headers
        for (String header : iRequestInfo.getHeaders()) {
            stringBuilder.append(header + NEW_LINE);
        }

        // Get Request body
        String requestBody = getRaw(iRequestInfo, iHttpRequestResponse.getRequest());
        if (requestBody.length() > 0) {
            stringBuilder.append(NEW_LINE + requestBody);
        }

        requestTextArea.setText(stringBuilder.toString());
    }

    /**
     * Save Request
     *
     * @param iRequestInfo iRequestInfo
     */
    public void saveRequest(IRequestInfo iRequestInfo, IHttpRequestResponse iHttpRequestResponse) {
        Integer rowIndex = this.iRequestInfoList.size();
        requestTable.setValueAt(rowIndex + 1, rowIndex, RequestTable.NO_COLUMN_INDEX);
        requestTable.setValueAt(true, rowIndex, RequestTable.ENABLED_COLUMN_INDEX);
        requestTable.setValueAt(iRequestInfo.getUrl().getHost(), rowIndex, RequestTable.HOST_COLUMN_INDEX);
        requestTable.setValueAt(iRequestInfo.getMethod(), rowIndex, RequestTable.METHOD_COLUMN_INDEX);
        requestTable.setValueAt(iRequestInfo.getUrl().getPath(), rowIndex, RequestTable.URL_COLUMN_INDEX);
        this.iRequestInfoList.add(iRequestInfo);
        this.iHttpRequestResponseList.add(iHttpRequestResponse);
    }

    /**
     *
     */
    public void sendRequest() {
        for (IHttpRequestResponse iHttpRequestResponse : iHttpRequestResponseList) {
            IHttpRequestResponse response = iBurpExtenderCallbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), iHttpRequestResponse.getRequest());
            requestResponseTextArea.append(new String(response.getResponse(), StandardCharsets.UTF_8));
        }
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
}
