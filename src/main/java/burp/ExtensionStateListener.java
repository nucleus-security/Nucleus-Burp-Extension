/*
 * Copyright (c) 2021 Nucleus Security - All Rights Reserved
 */
package burp;

import java.util.logging.Level;
import java.util.logging.Logger;

public class ExtensionStateListener implements IExtensionStateListener {
    
    private Thread thread;
    
    @Override
    public void extensionUnloaded() {
       if(thread != null) {
           try {
               thread.join();
               thread.interrupt();
           } catch (InterruptedException ex) {
               Logger.getLogger(ExtensionStateListener.class.getName()).log(Level.SEVERE, null, ex);
           }
       }
    }
    
    public void setThread(Thread thread) {
        this.thread = thread;
    }
   
}
