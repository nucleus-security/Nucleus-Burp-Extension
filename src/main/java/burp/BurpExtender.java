/*
 * Copyright (c) 2021 Nucleus Security - All Rights Reserved
 */
package burp;

import com.nucleussec.burpextension.view.MainView;
import com.nucleussec.burpextension.view.Tab;

public class BurpExtender implements IBurpExtender {

    private ExtensionStateListener esl;
    private MainView mainView;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.esl = new ExtensionStateListener();
        this.mainView = new MainView(callbacks, esl);
        callbacks.setExtensionName("Nucleus");
        callbacks.customizeUiComponent(mainView);
        callbacks.addSuiteTab(new Tab(mainView));
        callbacks.registerExtensionStateListener(esl);
    }
   
    
}
