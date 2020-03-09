/*
 * Copyright (c) 2020 Nucleus Security - All Rights Reserved
 */
package com.nucleussec.burpextension.view;

import burp.ExtensionStateListener;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import com.nucleussec.burpextension.controllers.NucleusApi;
import com.nucleussec.burpextension.utils.GlobalUtils;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.prefs.Preferences;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.swing.DefaultListModel;
import javax.swing.JOptionPane;

public class MainView extends javax.swing.JPanel {
    
    private IBurpExtenderCallbacks callbacks;
    private Preferences prefs;
    private NucleusApi nucleusApi;
    private ExtensionStateListener esl;
    private Thread thread;
    
    /**
     * Creates new form MainView
     */
    public MainView(IBurpExtenderCallbacks callbacks, ExtensionStateListener esl) {
        this.callbacks = callbacks;
        this.esl = esl;
        this.prefs = Preferences.userRoot().node(this.getClass().getName());
        this.nucleusApi = new NucleusApi(this, prefs);
        initComponents();
        
        populateScanUrlsList();
        
        String instanceUrl = prefs.get("instance_url", "");
        txtNucleusInstanceURL.setText(instanceUrl);
        
        String apiKey = prefs.get("x-apikey", "");
        if(!apiKey.isEmpty()) {
            pwApiKey.setText(apiKey);
        }
        
        if(!apiKey.isEmpty() && !instanceUrl.isEmpty()) {
            populateProjectsComboBox();
        }
    }
    
    private void populateProjectsComboBox() {
        cbProjects.removeAllItems();
        try {
            nucleusApi.getProjects().forEach((projectId, projectName) -> {
                cbProjects.addItem(projectId + " - " + projectName);
            });
        } catch (IOException ex) {
            Logger.getLogger(MainView.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void populateScanUrlsList() {
        LinkedHashSet<String> targetUrls = new LinkedHashSet<>();

        for(IHttpRequestResponse reqResp : callbacks.getSiteMap("")) {
            String host = reqResp.getHttpService().getProtocol() + "://" + reqResp.getHttpService().getHost();
            targetUrls.add(host);
        }
        
        for(String targetUrl : targetUrls) 
            ((DefaultListModel)listScanUrls.getModel()).addElement(targetUrl);
    }
    
    private IScanIssue[] getScanIssues() {
        List<String> selectedUrls = listScanUrls.getSelectedValuesList();
        ArrayList<IScanIssue> scanIssues = new ArrayList();
        
        if(!selectedUrls.isEmpty()) {
            for(String selectedUrl : selectedUrls) {
                Collections.addAll(scanIssues, callbacks.getScanIssues(selectedUrl));
            }
        } else {
            Collections.addAll(scanIssues, callbacks.getScanIssues(""));
        }
        
        return scanIssues.toArray(new IScanIssue[scanIssues.size()]);
    }
    
    private void zipFile(File file) {
        try {
            FileOutputStream fos = new FileOutputStream(System.getenv("USERPROFILE")+"\\AppData\\Local\\Temp\\" + file.getName()+".zip");
            ZipOutputStream zipOut = new ZipOutputStream(fos);
            FileInputStream fis = new FileInputStream(file);
            ZipEntry zipEntry = new ZipEntry(file.getName());
            zipOut.putNextEntry(zipEntry);
            byte[] bytes = new byte[1024];
            int length;
            while((length = fis.read(bytes)) >= 0) {
                zipOut.write(bytes, 0, length);
            }
            zipOut.close();
            fis.close();
            fos.close();
        } catch (IOException ex) {
            Logger.getLogger(MainView.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void checkIfFileIsWritten(boolean isCompletelyWritten) {
        while(!isCompletelyWritten) {
            try {
                Thread.sleep(1000);
                jProgressBar.setValue(45);
            } catch (InterruptedException ex) {
                Logger.getLogger(MainView.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
    private void pushToNucleus() {
        long currentTime = System.currentTimeMillis();
        String fileName = System.getenv("USERPROFILE")+"\\AppData\\Local\\Temp\\nucleusBurpExtension-" + currentTime + ".xml";
        File file = new File(fileName);
        setProgressBar(15);
       thread = new Thread(new Runnable() {
            @Override
            public void run() {
                callbacks.generateScanReport("xml", getScanIssues(), file);
                jProgressBar.setValue(30);
                
                checkIfFileIsWritten(GlobalUtils.isCompletelyWritten(file));
                
                zipFile(file);
                String zipFileName = System.getenv("USERPROFILE")+"\\AppData\\Local\\Temp\\" + file.getName() + ".zip";
                File zipFile = new File(zipFileName);
                
                checkIfFileIsWritten(GlobalUtils.isCompletelyWritten(zipFile));
        
                try {
                    nucleusApi.uploadScanFile(zipFile, zipFile.getName());
                    jProgressBar.setValue(100);
                } catch (IOException ex) {
                    System.out.println(ex.getMessage());
                }
            }
        });
       esl.setThread(thread);
       thread.start();
    }
    
    public String getCurrentSelectedProject() {
        String selectedItem = (String) cbProjects.getSelectedItem();
        return selectedItem.split("-")[0].replaceAll(" ", "");
    }
    
    public String getInstanceUrl() {
        String url = txtNucleusInstanceURL.getText();
        if(!url.contains("://"))
            url = "http://" + url;
        if(!url.substring(url.length()-1).equals("/"))
            url = url + "/";
        return url;
    }
    
    public void setProgressBar(int n) {
        jProgressBar.setValue(n);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        cbProjects = new javax.swing.JComboBox<>();
        btnPushToNucleus = new javax.swing.JButton();
        jProgressBar = new javax.swing.JProgressBar();
        jLabel4 = new javax.swing.JLabel();
        btnSyncWithNucleus = new javax.swing.JButton();
        pwApiKey = new javax.swing.JPasswordField();
        jLabel5 = new javax.swing.JLabel();
        txtNucleusInstanceURL = new javax.swing.JTextField();
        jScrollPane1 = new javax.swing.JScrollPane();
        listScanUrls = new javax.swing.JList<>();
        jLabel6 = new javax.swing.JLabel();

        jPanel1.setBorder(javax.swing.BorderFactory.createEtchedBorder());

        jLabel1.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel1.setText("Nucleus Security Burp Extension");

        jLabel2.setText("Nucleus API Key:");

        jLabel3.setText("Project:");

        btnPushToNucleus.setText("Push All Scan Issues to Nucleus");
        btnPushToNucleus.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnPushToNucleusActionPerformed(evt);
            }
        });

        jLabel4.setText("Scan Upload Status");

        btnSyncWithNucleus.setText("Sync with Nucleus");
        btnSyncWithNucleus.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnSyncWithNucleusActionPerformed(evt);
            }
        });

        pwApiKey.setText("jPasswordField1");

        jLabel5.setText("Nucleus Instance URL:");

        txtNucleusInstanceURL.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                txtNucleusInstanceURLKeyReleased(evt);
            }
        });

        listScanUrls.setModel(new DefaultListModel<String>());
        jScrollPane1.setViewportView(listScanUrls);

        jLabel6.setText("Scan URLs to Upload:");

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(jLabel5)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(txtNucleusInstanceURL))
                    .addComponent(jScrollPane1)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                .addComponent(jLabel1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(btnPushToNucleus)
                                .addGroup(javax.swing.GroupLayout.Alignment.LEADING, jPanel1Layout.createSequentialGroup()
                                    .addComponent(jLabel3)
                                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                    .addComponent(cbProjects, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addGroup(javax.swing.GroupLayout.Alignment.LEADING, jPanel1Layout.createSequentialGroup()
                                    .addComponent(jLabel2)
                                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                    .addComponent(pwApiKey, javax.swing.GroupLayout.PREFERRED_SIZE, 188, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                    .addComponent(btnSyncWithNucleus))
                                .addGroup(javax.swing.GroupLayout.Alignment.LEADING, jPanel1Layout.createSequentialGroup()
                                    .addComponent(jLabel4)
                                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                    .addComponent(jProgressBar, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                            .addComponent(jLabel6))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel5)
                    .addComponent(txtNucleusInstanceURL, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(btnSyncWithNucleus)
                    .addComponent(pwApiKey, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(cbProjects, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jLabel6)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 117, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(4, 4, 4)
                        .addComponent(jLabel4))
                    .addComponent(jProgressBar, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(btnPushToNucleus)
                .addGap(23, 23, 23))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(276, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(16, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void btnPushToNucleusActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnPushToNucleusActionPerformed
        String errors = "";
        if (prefs.get("instance_url", "").isEmpty() || prefs.get("x-apikey", "").isEmpty()) {
            JOptionPane.showMessageDialog(this, "Some fields appear to be empty. Please fill in these fields and try again.", "Error has occured", JOptionPane.ERROR_MESSAGE);
        } else pushToNucleus();
        
    }//GEN-LAST:event_btnPushToNucleusActionPerformed

    private void btnSyncWithNucleusActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnSyncWithNucleusActionPerformed
        char[] apiKey = pwApiKey.getPassword();
        if(apiKey.length > 0) {
            prefs.put("x-apikey", String.valueOf(apiKey));
            populateProjectsComboBox();
        }
    }//GEN-LAST:event_btnSyncWithNucleusActionPerformed

    private void txtNucleusInstanceURLKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtNucleusInstanceURLKeyReleased
        prefs.put("instance_url", txtNucleusInstanceURL.getText());
    }//GEN-LAST:event_txtNucleusInstanceURLKeyReleased


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnPushToNucleus;
    private javax.swing.JButton btnSyncWithNucleus;
    private javax.swing.JComboBox<String> cbProjects;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JProgressBar jProgressBar;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JList<String> listScanUrls;
    private javax.swing.JPasswordField pwApiKey;
    private javax.swing.JTextField txtNucleusInstanceURL;
    // End of variables declaration//GEN-END:variables
}
