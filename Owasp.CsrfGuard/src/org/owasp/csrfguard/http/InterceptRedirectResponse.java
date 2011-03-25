package org.owasp.csrfguard.http;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

public class InterceptRedirectResponse extends HttpServletResponseWrapper {
	
	private HttpServletResponse response = null;
	
	private String location = null;
	
	public InterceptRedirectResponse(HttpServletResponse response) {
		super(response);
		this.response = response;
	}

	@Override
	public void sendRedirect(@SuppressWarnings("hiding") String location) throws IOException {
		this.location = location;
	}
	
	@Override
	public HttpServletResponse getResponse() {
		return response;
	}
	
	public void sendRedirect(String target, String tokenName, String tokenValue) throws IOException {
		StringBuilder sb = new StringBuilder();
		
		sb.append(target);
		
		if(location.contains("?")) {
			sb.append('&');
		} else {
			sb.append('?');
		}
		
		sb.append(tokenName);
		sb.append('=');
		sb.append(tokenValue);
		
		response.sendRedirect(sb.toString());
	}
	
	public String getLocation() {
		return location;
	}
	
}
