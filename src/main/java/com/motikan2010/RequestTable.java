package com.motikan2010;

import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;

public class RequestTable extends DefaultTableModel implements TableModelListener {

    private Object[][] tableData;

    private static final String[] COLUMN_NAMES = {"No", "", "Host", "Method", "URL"};

    private static final int TABLE_ROW_COUNT = 10;
    private static final int TABLE_COLUMN_COUNT = 5;

    public static final int NO_COLUMN_INDEX      = 0;
    public static final int ENABLED_COLUMN_INDEX = 1;
    public static final int HOST_COLUMN_INDEX    = 2;
    public static final int METHOD_COLUMN_INDEX  = 3;
    public static final int URL_COLUMN_INDEX     = 4;

    public RequestTable() {
        tableData = new Object[TABLE_ROW_COUNT][TABLE_COLUMN_COUNT];
        for(int i = 0; i < TABLE_ROW_COUNT; i++) {
            tableData[i][NO_COLUMN_INDEX]        = "";
            tableData[i][ENABLED_COLUMN_INDEX]   = false;
            tableData[i][HOST_COLUMN_INDEX]      = "";
            tableData[i][METHOD_COLUMN_INDEX]    = "";
            tableData[i][URL_COLUMN_INDEX]       = "";
        }
        addTableModelListener(this);
    }

    public Object[][] getTabledata() {
        return this.tableData;
    }

    public int getColumnCount() {
        return TABLE_COLUMN_COUNT;
    }

    public int getRowCount() {
        return TABLE_ROW_COUNT;
    }

    public Object getValueAt(int rowIndex, int columnIndex) {
        return tableData[rowIndex][columnIndex];
    }

    @Override
    public String getColumnName(int columnIndex) {
        return COLUMN_NAMES[columnIndex];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return getValueAt(0, columnIndex).getClass();
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return true;
    }

    @Override
    public void setValueAt(Object value, int rowIndex, int columnIndex) {
        tableData[rowIndex][columnIndex] = value;
        fireTableDataChanged();
    }

    public void tableChanged(TableModelEvent e) {

    }
}
