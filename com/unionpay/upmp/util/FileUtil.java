package com.unionpay.upmp.util;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.HashMap;

import org.apache.jorphan.logging.LoggingManager;
import org.apache.log.Logger;

public class FileUtil {
	public static HashMap<String, String> extMap;
	private static Logger logger = LoggingManager.getLoggerForClass();
	
	/**
     * 读文件，将文件内容读出为String
     * @param file
     * @param encode
     * @return
     */
    public static String loadFileAsString(String file) {
        return loadFileAsString(new File(file), "UTF-8");
    }

	public static String loadFileAsString(File file, String encoding) {
		
		if(!file.exists()){
			return null;
		}
		RandomAccessFile r = null;
		try {
			r = new RandomAccessFile(file, "r");

			byte[] b = new byte[(int) r.length()];
			r.read(b);

			return new String(b, encoding);

		} catch (Exception e) {
			logger.error(e.getMessage());
		} finally {
			try {
				r.close();
			} catch (IOException e) {
				logger.error(e.getMessage());
			}
		}
		return null;
	}
}
