package burp;

import com.motikan2010.RequestContextMenu;
import com.motikan2010.RequestFlowTab;

import javax.swing.*;
import java.awt.*;
import java.util.LinkedList;
import java.util.List;

public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory {

    private static final String EXTENSION_NAME = "CSRF Bypass Route";

    private IBurpExtenderCallbacks iBurpExtenderCallbacks;
    private RequestFlowTab requestFlowTab;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName(EXTENSION_NAME);
        this.iBurpExtenderCallbacks = callbacks;

        // Init Request Tab
        SwingUtilities.invokeLater(() -> {
            requestFlowTab = RequestFlowTab.getInstance(callbacks);
            requestFlowTab.render();
            this.iBurpExtenderCallbacks.addSuiteTab(BurpExtender.this);
        });

        callbacks.registerContextMenuFactory(this);
    }

    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        IHttpRequestResponse[] httpRequestResponseArray = iContextMenuInvocation.getSelectedMessages();
        if (null == httpRequestResponseArray) {
            return null;
        }

        List<JMenuItem> jMenuItemList = new LinkedList<>();
        
        JMenuItem requestJMenuItem = new JMenuItem("Save Request");
        requestJMenuItem.addMouseListener(new RequestContextMenu(this.iBurpExtenderCallbacks, httpRequestResponseArray, requestFlowTab));
        jMenuItemList.add(requestJMenuItem);

        return jMenuItemList;
    }

    @Override
    public String getTabCaption() {
        return EXTENSION_NAME;
    }

    @Override
    public Component getUiComponent() {
        return requestFlowTab;
    }
}
