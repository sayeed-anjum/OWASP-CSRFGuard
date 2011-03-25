package org.owasp.csrfguard.http;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;

public class MultipartHttpServletRequest extends HttpServletRequestWrapper {
	
	private Map<String, List<String>> parameters = new HashMap<String, List<String>>();
	
	public static boolean isMultipartRequest(HttpServletRequest request) {
		return ServletFileUpload.isMultipartContent(request);
	}
	
	public MultipartHttpServletRequest(HttpServletRequest request) throws IOException {
		super(request);
		
		try {
			@SuppressWarnings("unchecked")
			List<FileItem> fileItems = new ServletFileUpload(new DiskFileItemFactory()).parseRequest(request);
			
			for(FileItem fileItem : fileItems) {
				if(fileItem.isFormField()) {
					List<String> values = parameters.get(fileItem.getFieldName());
					
					if(values == null) {
						values = new ArrayList<String>();
						parameters.put(fileItem.getFieldName(), values);
					}
					
					values.add(fileItem.getString());
				} else {
					/** skip files **/
				}
			}
			
		} catch (FileUploadException fue) {
			throw new IOException(fue.getLocalizedMessage());
		}
	}
	
	@Override
	public Enumeration<String> getParameterNames() {
		return Collections.enumeration(parameters.keySet());
	}
	
	@Override
	public String getParameter(String name) {
		String value = null;
		List<String> values = parameters.get(name);
		
		if(values != null) {
			if(values.size() > 0) {
				value = values.get(0);
			} else {
				value = "";
			}
		}
		
		return value;
	}
	
	@Override
	public String[] getParameterValues(String name) {
		String[] values = null;
		List<String> list = parameters.get(name);
		
		if(list != null) {
			values = list.toArray(new String[list.size()]);
		}
		
		return values;
	}
	
	@Override
	public Map<String, List<String>> getParameterMap() {
		return Collections.unmodifiableMap(parameters);
	}
}
