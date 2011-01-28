/**
 * The OWASP CSRFGuard Project, BSD License
 * Eric Sheridan (eric.sheridan@owasp.org), Copyright (c) 2011 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of OWASP nor the names of its contributors may be used
 *       to endorse or promote products derived from this software without specific
 *       prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package org.owasp.csrfguard;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

import org.owasp.csrfguard.log.LogLevel;
import org.owasp.csrfguard.util.*;

public final class CsrfGuardFilter implements Filter {

	private final static String CONFIG_PARAM = "config";
	
	private final static String PRINT_CONFIG_PARAM = "print-config";
	
	private CsrfGuard csrfGuard = null;

	@Override
	public void destroy() {
		// TODO Auto-generated method stub
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
		/** only work with HttpServletRequest objects **/
		if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
			csrfGuard.getLogger().log(String.format("CsrfGuard analyzing request %s", ((HttpServletRequest) request).getRequestURI()));

			doCsrfGuard((HttpServletRequest) request, (HttpServletResponse) response, filterChain);
		} else {
			csrfGuard.getLogger().log(LogLevel.Warning, String.format("CsrfGuard does not know how to work with requests of class %s ", request.getClass().getName()));
			
			filterChain.doFilter(request, response);
		}
	}

	private void doCsrfGuard(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
		if (csrfGuard.isFirstRequest(request)) {
			csrfGuard.updateTokens(request);
			csrfGuard.writeLandingPage(request, response);
		} else if (csrfGuard.isValidRequest(request, response)) {
			csrfGuard.updateTokens(request);
			filterChain.doFilter(request, response);
		}
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		String config = filterConfig.getInitParameter(CONFIG_PARAM);
		ServletContext context = filterConfig.getServletContext();

		if (config == null) {
			throw new ServletException(String.format("failure to specify filter init-param - %s", CONFIG_PARAM));
		}

		InputStream is = null;

		try {
			is = getResourceStream(config, context);
			csrfGuard = CsrfGuard.newInstance(is);
		} catch (Exception e) {
			throw new ServletException(e);
		} finally {
			Streams.close(is);
		}

		String printConfig = filterConfig.getInitParameter(PRINT_CONFIG_PARAM);

		if (printConfig != null && Boolean.parseBoolean(printConfig)) {
			filterConfig.getServletContext().log(String.valueOf(csrfGuard));
		}
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
