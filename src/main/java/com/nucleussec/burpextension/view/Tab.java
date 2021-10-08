/*
 * Copyright (c) 2021 Nucleus Security - All Rights Reserved
 */
package com.nucleussec.burpextension.view;

import burp.ITab;
import java.awt.Component;

public class Tab implements ITab {
    
    private MainView mainView;
    
    public Tab(MainView mainView) {
        this.mainView = mainView;
    }

    /**
     * Gets the tab name for the extension
     * @return Nucleus 
     */
    @Override
    public String getTabCaption() {
        return "Nucleus";
    }

    /**
     * Get the main UI component
     * @return main component
     */
    @Override
    public Component getUiComponent() {
        return mainView;
    }
    
}
