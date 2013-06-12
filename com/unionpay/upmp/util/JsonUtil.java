package com.unionpay.upmp.util;

import java.text.SimpleDateFormat;
import java.util.Map;

import org.apache.jorphan.logging.LoggingManager;
import org.apache.log.Logger;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.SerializationConfig;

public class JsonUtil
{
  private static final Logger logger = LoggingManager.getLoggerForClass();

  private static final ObjectMapper mapper = new ObjectMapper();
  //private static final String DATE_FORMAT = "yyyy-MM-dd";

  public static <T> T fromJson(String json, Class<T> t)
  {
    if (json == null)
      return null;
    try
    {
      return mapper.readValue(json, t);
    } catch (Exception e) {
      logger.info("Cannot parse json string to Object. Json: <" + json + ">, Object class: <" + t.getName() + ">.", e);
    }

    return null;
  }

//  public static <T> T fromFile(String file, Class<T> t)
//  {
//    File f = new File(file);
//
//    if ((!f.exists()) || (!f.isFile())) {
//      logger.warn("File[" + file + "] does not exist.");
//      return null;
//    }
//
//    return fromJson(FileUtil.loadFileAsString(file), t);
//  }

  public static <T> T fromJsonWithException(String json, Class<T> t) {
    try {
      return mapper.readValue(json, t);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static <T> T fromMap(Map<?, ?> map, Class<T> t)
  {
    if (map == null)
      return null;
    try
    {
      return mapper.readValue(toJson(map), t);
    } catch (Exception e) {
      logger.info("Cannot parse map to Object. Map: <" + map + ">, Object class: <" + t.getName() + ">.", e);
    }

    return null;
  }

  public static String toJson(Object obj) {
    try {
      return mapper.writeValueAsString(obj);
    } catch (Exception e) {
      logger.warn(e.getMessage());
    }
    return "{}";
  }

  static
  {
    mapper.configure(SerializationConfig.Feature.FAIL_ON_EMPTY_BEANS, false);
    mapper.configure(SerializationConfig.Feature.INDENT_OUTPUT, true);
    mapper.getSerializationConfig().setDateFormat(new SimpleDateFormat("yyyy-MM-dd"));
  }
}
