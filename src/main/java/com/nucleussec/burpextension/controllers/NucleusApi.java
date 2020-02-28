/*
 * Copyright (c) 2020 Nucleus Security - All Rights Reserved
 */
package com.nucleussec.burpextension.controllers;

import com.nucleussec.burpextension.utils.GlobalUtils;
import com.nucleussec.burpextension.view.MainView;
import java.io.File;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.prefs.Preferences;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.json.JSONArray;
import org.json.JSONObject;

public class NucleusApi {
    
    private OkHttpClient client;
    private MainView mainView;
    private Preferences prefs;
    
    public NucleusApi(MainView mainView, Preferences prefs) {
        this.mainView = mainView;
        this.prefs = prefs;
        try {
            final TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(java.security.cert.X509Certificate[] chain,
                            String authType) throws CertificateException {
                    }
                    
                    @Override
                    public void checkServerTrusted(java.security.cert.X509Certificate[] chain,
                            String authType) throws CertificateException {
                    }
                    
                    @Override
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
            };
            final SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            this.client = new OkHttpClient.Builder()
                    .sslSocketFactory(sslSocketFactory, (X509TrustManager)trustAllCerts[0])
                    .hostnameVerifier(new HostnameVerifier() {
                        @Override
                        public boolean verify(String string, SSLSession ssls) {
                            return true;
                        }
                    })
                    .build();
        } catch (KeyManagementException ex) {
            Logger.getLogger(NucleusApi.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(NucleusApi.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
        
    public void uploadScanFile(File scanFile, String scanFileName) throws IOException {
        RequestBody requestBody = new MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("scan_description", "Uploaded via Nucleus Burp Extension")
                .addFormDataPart(scanFileName, scanFile.getName(),
                        RequestBody.create(scanFile, MediaType.parse("application/xml")))
                .build();
        mainView.setProgressBar(60);
        Request request = new Request.Builder().url(mainView.getInstanceUrl() + "nucleus/api/projects/" + mainView.getCurrentSelectedProject() + "/scans")
                .addHeader("x-apikey", prefs.get("x-apikey", "")).post(requestBody).build();
        mainView.setProgressBar(75);
        Response response = client.newCall(request).execute();
        mainView.setProgressBar(90);
    }
    
    public HashMap<String, String> getProjects() throws IOException {
        HashMap<String, String> projects = new HashMap<>();
        Request request = new Request.Builder()
                .url(mainView.getInstanceUrl() + "nucleus/api/projects")
                .addHeader("x-apikey", prefs.get("x-apikey", ""))
                .build();
        Response response = client.newCall(request).execute();
        
        JSONArray jsonArray = new JSONArray(response.body().string());
        jsonArray.forEach(o -> {
            JSONObject jsonObj = (JSONObject) o;
            projects.put(jsonObj.getString("project_id"), jsonObj.getString("project_name"));
        });
        return projects;
    }
}
