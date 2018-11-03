package org.gradle.util;

/**
 * 訊息搜集器
 * @author Clare
 * @date 2017年6月6日 
 */
public class MessageCollection {
	private StringBuffer messages;
	private boolean debug = false;
	
	public MessageCollection(boolean debug){
		this.debug = debug;
		if(this.debug){
			messages = new StringBuffer();
		}
	}
	
	public void log(String message){
		if(this.debug){
			messages.append("\n"+message);
		}
	}

	@Override
	public String toString() {
		if(messages==null){
			return "";
		}
		return messages.toString();
	}
}
