## OWASP CSRFGuard 3.0

[](http://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project)
Eric Sheridan (eric.sheridan@owasp.org), Copyright (c) 2011
BSD License, All rights reserved.

## Overview

Welcome to the home of the OWASP CSRFGuard Project! OWASP CSRFGuard is a library that implements
a variant of the synchronizer token pattern to mitigate the risk of Cross-Site Request Forgery
(CSRF) attacks. The OWASP CSRFGuard library is integrated through the use of a JavaEE Filter and
exposes various automated and manual ways to integrate per-session or pseudo-per-request tokens
into HTML. When a user interacts with this HTML, CSRF prevention tokens (i.e. cryptographically
random synchronizer tokens) are submitted with the corresponding HTTP request. It is the
responsibility of OWASP CSRFGuard to ensure the token is present and is valid for the current HTTP
request. Any attempt to submit a request to a protected resource without the correct corresponding
token is viewed as a CSRF attack in progress and is discarded. Prior to discarding the request,
CSRFGuard can be configured to take one or more actions such as logging aspects of the request and
redirecting the user to a landing page. The latest release enhances this strategy to support the
optional verification of HTTP requests submitted using Ajax as well as the optional verification
of referrer headers.

## Project Lead

Eric Sheridan (eric.sheridan@owasp.org) is the lead and primary developer of the OWASP CSRFGuard
project. Aside from leading up CSRFGuard, Eric has contributed to or provided guidance
on numerous other OWASP projects including WebGoat, Stinger, CSRFTester, and Enterprise Security
API (ESAPI). He is a Principal Consultant at Aspect Security specializing in a wide variety of
application security activities including static analysis, penetration tests, code reviews, and
threat modeling. In his personal time... wait, what is that?

## License

OWASP CSRFGuard is offered under the BSD license (http://www.opensource.org/licenses/bsd-license.php)

## Email List

You can sign up for the OWASP CSRFGuard email list at https://lists.owasp.org/mailman/listinfo/owasp-csrfguard.
