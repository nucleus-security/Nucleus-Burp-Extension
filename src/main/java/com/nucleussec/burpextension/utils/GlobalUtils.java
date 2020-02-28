/*
 * Copyright (c) 2020 Nucleus Security - All Rights Reserved
 */
package com.nucleussec.burpextension.utils;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

public class GlobalUtils {
       
    //https://stackoverflow.com/a/11242648
    public static boolean isCompletelyWritten(File file) {
        RandomAccessFile stream = null;
        try {
            stream = new RandomAccessFile(file, "rw");
            return true;
        } catch (Exception e) {
            System.out.print("Skipping file " + file.getName() + " for this iteration due it's not completely written");
        } finally {
            if (stream != null) {
                try {
                    stream.close();
                } catch (IOException e) {
                    System.out.print("Exception during closing file " + file.getName());
                }
            }
        }
        return false;
    }
}
