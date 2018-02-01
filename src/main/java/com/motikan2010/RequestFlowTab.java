package com.motikan2010;

import burp.IRequestInfo;

import javax.swing.*;
import java.awt.*;
import java.util.LinkedList;
import java.util.List;

public class RequestFlowTab extends JPanel {

    private static final int PANEL_X = 10;
    private static final int PANEL_Y = 10;

    private static final int PANEL_WIDTH = 800;
    private static final int PANEL_HEIGHT = 110;

    private static RequestFlowTab panel;

    private Label syncTitleLabel;
    private JTable requestTable;
    private JScrollPane requestScrollPane;
    private List<IRequestInfo> iRequestInfoList;

    public static RequestFlowTab getInstance() {
        if (panel == null) {
            panel = new RequestFlowTab();
        }
        return panel;
    }

    public void render() {
        setLayout(null);
        iRequestInfoList = new LinkedList<>();

        syncTitleLabel = new Label("Request Flow");
        syncTitleLabel.setForeground(new Color(229, 137, 0));
        syncTitleLabel.setFont(new Font("Dialog", Font.BOLD, 15));

        requestTable = new JTable(new RequestTable());

        requestTable.getColumnModel().getColumn(RequestTable.NO_COLUMN_INDEX).setMinWidth(75);
        requestTable.getColumnModel().getColumn(RequestTable.ENABLED_COLUMN_INDEX).setMinWidth(75);
        requestTable.getColumnModel().getColumn(RequestTable.HOST_COLUMN_INDEX).setPreferredWidth(150);
        requestTable.getColumnModel().getColumn(RequestTable.METHOD_COLUMN_INDEX).setPreferredWidth(150);
        requestTable.getColumnModel().getColumn(RequestTable.URL_COLUMN_INDEX).setPreferredWidth(150);

        requestScrollPane = new JScrollPane(requestTable);
        requestScrollPane.setLocation(PANEL_X, PANEL_Y);
        requestScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

        // クリアボタン
        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> {

        });

        syncTitleLabel.setBounds(PANEL_X, PANEL_Y, 145, 23);
        requestScrollPane.setLocation(PANEL_X, PANEL_Y + 25);
        requestScrollPane.setSize(PANEL_WIDTH, PANEL_HEIGHT + 25);

        add(syncTitleLabel);
        add(requestScrollPane);
        add(clearButton);
    }

    /**
     * Save Request
     *
     * @param iRequestInfo iRequestInfo
     */
    public void saveRequest(IRequestInfo iRequestInfo) {
        this.iRequestInfoList.add(iRequestInfo);
    }
}
