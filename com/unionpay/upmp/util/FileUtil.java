package com.unionpay.upmp.util;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

import org.apache.jorphan.logging.LoggingManager;
import org.apache.log.Logger;

public class FileUtil {
	
	private static Logger logger = LoggingManager.getLoggerForClass();

	/**
	 * read in file and convert to string
	 * @param file
	 * @param encode
	 * @return
	 */
	public static String loadFileAsString(String file) {
		File objFile = new File(file);
		if(objFile.exists()){
			RandomAccessFile randAF = null;
			try {
				randAF = new RandomAccessFile(objFile, "r");
				byte[] bytes = new byte[(int) randAF.length()];
				randAF.read(bytes);
				return new String(bytes, UPMPConstant.upmp_charset);
			} catch (Exception e) {
				logger.error(e.getMessage());
			} finally {
				try {
					randAF.close();
				} catch (IOException e) {
					logger.error(e.getMessage());
				}
			}
		}
		return null;	
	}
}
