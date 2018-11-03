package org.gradle.bean;

import lombok.Getter;
import lombok.Setter;

/**
 * 
 * 驗證請求結果
 * @author Clare 2018年6月1日 下午2:43:39
 */
public class VerifyRequestResult{
	private StringBuffer logBuffer;
	private boolean trace;
	
	@Getter
	@Setter
	private boolean save;
	
	public VerifyRequestResult( boolean trace) {
		this.trace = trace;
		if(trace) {
			logBuffer = new StringBuffer();
		}
	}
	
	public void log(String message){
		if(this.trace){
			logBuffer.append(message+"\n");
		}
	}

	@Override
	public String toString() {
		if(logBuffer==null){
			return "";
		}
		return logBuffer.toString();
	}
}
