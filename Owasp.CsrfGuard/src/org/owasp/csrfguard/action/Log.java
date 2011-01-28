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
package org.owasp.csrfguard.action;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.csrfguard.CsrfGuard;
import org.owasp.csrfguard.CsrfGuardException;
import org.owasp.csrfguard.log.LogLevel;

public final class Log extends AbstractAction {

	@Override
	public void execute(HttpServletRequest request, HttpServletResponse response, CsrfGuardException csrfe, CsrfGuard csrfGuard) throws CsrfGuardException {
		String logMessage = getParameter("Message");

		/** Exception Information **/
		logMessage = logMessage.replaceAll("%exception%", String.valueOf(csrfe));
		logMessage = logMessage.replaceAll("%exception_message%", csrfe.getLocalizedMessage());

		/** Remote Network Information **/
		logMessage = logMessage.replaceAll("%remote_ip%", request.getRemoteAddr());
		logMessage = logMessage.replaceAll("%remote_host%", request.getRemoteHost());
		logMessage = logMessage.replaceAll("%remote_port%", String.valueOf(request.getRemotePort()));

		/** Local Network Information **/
		logMessage = logMessage.replaceAll("%local_ip%", request.getLocalAddr());
		logMessage = logMessage.replaceAll("%local_host%", request.getLocalName());
		logMessage = logMessage.replaceAll("%local_port%", String.valueOf(request.getLocalPort()));

		/** Requested Resource Information **/
		logMessage = logMessage.replaceAll("%request_uri%", request.getRequestURI());
		logMessage = logMessage.replaceAll("%request_url%", request.getRequestURL().toString());

		/** JavaEE Principal Information **/
		if (request.getRemoteUser() != null) {
			logMessage = logMessage.replaceAll("%user%", request.getRemoteUser());
		} else {
			logMessage = logMessage.replaceAll("%user", "<anonymous>");
		}

		csrfGuard.getLogger().log(LogLevel.Error, logMessage);
	}
	
}
