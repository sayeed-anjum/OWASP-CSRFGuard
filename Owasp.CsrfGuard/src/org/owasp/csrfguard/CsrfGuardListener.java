package org.owasp.csrfguard;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

import org.owasp.csrfguard.util.Streams;

public class CsrfGuardListener implements HttpSessionListener {

	private final static String CONFIG_PARAM = "Owasp.CsrfGuard.Config";
	
	private final static String CONFIG_PRINT_PARAM = "Owasp.CsrfGuard.Config.Print";
	
	@Override
	public void sessionCreated(HttpSessionEvent event) {
		HttpSession session = event.getSession();
		CsrfGuard csrfGuard = newInstance(session.getServletContext());
		
		session.setAttribute(CsrfGuard.SESSION_KEY, csrfGuard);
		csrfGuard.updateToken(session);
	}

	@Override
	public void sessionDestroyed(HttpSessionEvent event) {
		/** nothing to do **/
	}
	
	private CsrfGuard newInstance(ServletContext context) {
		CsrfGuard csrfGuard = null;
		String config = context.getInitParameter(CONFIG_PARAM);
		
		if (config == null) {
			throw new RuntimeException(String.format("failure to specify context init-param - %s", CONFIG_PARAM));
		}

		InputStream is = null;

		try {
			is = getResourceStream(config, context);
			csrfGuard = CsrfGuard.newInstance(is);
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			Streams.close(is);
		}

		String printConfig = context.getInitParameter(CONFIG_PRINT_PARAM);

		if (printConfig != null && Boolean.parseBoolean(printConfig)) {
			context.log(String.valueOf(csrfGuard));
		}
		
		return csrfGuard;
	}

	private InputStream getResourceStream(String resourceName, ServletContext context) throws IOException {
		InputStream is = null;

		/** try classpath **/
		is = getClass().getClassLoader().getResourceAsStream(resourceName);

		/** try web context **/
		if (is == null) {
			String fileName = context.getRealPath(resourceName);
			File file = new File(fileName);

			if (file.exists()) {
				is = new FileInputStream(fileName);
			}
		}

		/** try current directory **/
		if (is == null) {
			File file = new File(resourceName);

			if (file.exists()) {
				is = new FileInputStream(resourceName);
			}
		}

		/** fail if still empty **/
		if (is == null) {
			throw new IOException(String.format("unable to locate resource - %s", resourceName));
		}

		return is;
	}

}
