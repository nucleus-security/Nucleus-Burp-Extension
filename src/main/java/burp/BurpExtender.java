/*
 * Copyright (c) 2020 Nucleus Security - All Rights Reserved
 */
package burp;

import com.nucleussec.burpextension.controllers.NucleusApi;
import com.nucleussec.burpextension.utils.GlobalUtils;
import com.nucleussec.burpextension.view.MainView;
import com.nucleussec.burpextension.view.Tab;

public class BurpExtender implements IBurpExtender {

    private MainView mainView;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.mainView = new MainView(callbacks);
        callbacks.setExtensionName("Nucleus");
        callbacks.customizeUiComponent(mainView);
        callbacks.addSuiteTab(new Tab(mainView));
    }
   
    
}
