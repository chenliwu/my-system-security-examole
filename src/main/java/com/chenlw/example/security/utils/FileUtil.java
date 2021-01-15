package com.chenlw.example.security.utils;

import java.io.*;

public class FileUtil {
    public static void writeFile(String filePath, byte[] data) throws IOException {
        RandomAccessFile raf = null;
        try {
            raf = new RandomAccessFile(filePath, "rw");
            raf.write(data);
        } finally {
            if (raf != null) {
                raf.close();
            }
        }
    }

    public static byte[] readFile(String filePath) throws IOException {
        RandomAccessFile raf = null;
        byte[] data;
        try {
            raf = new RandomAccessFile(filePath, "r");
            data = new byte[(int) raf.length()];
            raf.read(data);
            return data;
        } finally {
            if (raf != null) {
                raf.close();
            }
        }
    }

    /**
     * 把输入流的内容转化成字符串
     *
     * @param inputStream
     * @param charsetName
     * @return 字符串
     */
    public static String readInputStream(InputStream inputStream, String charsetName) throws IOException {
        if (inputStream == null) {
            return null;
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            int length = 0;
            byte[] buffer = new byte[1024];
            while ((length = inputStream.read(buffer)) != -1) {
                baos.write(buffer, 0, length);
            }
            //或者用这种方法
            //byte[] result=baos.toByteArray();
            //return new String(result);
            return baos.toString(charsetName);
        } catch (Exception e) {
            e.printStackTrace();
            throw new IOException(e);
        } finally {
            baos.close();
            inputStream.close();
        }
    }


}
