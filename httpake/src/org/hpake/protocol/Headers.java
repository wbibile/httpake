package org.hpake.protocol;

import org.hpake.SubjectConfirmation;

/**
 * Contains definitions for standard and custom headers used by HttPake.
 * @author Wiraj Bibile
 *
 */
public interface Headers
{
	/**
	 * Standard HTTP "WWW-Authenticate" response header.
	 */
	static final String WWW_AUTHENTICATE= "WWW-Authenticate";
	
	/**
	 * Standard HTTP "Authorization" request header.
	 */
	static final String AUTHORIZATION = "Authorization";
	
	/**
	 * Custom HttPake header used to exchange Diffie-Helmen public data.
	 * When used as a response header carries P,g,A (=g^a%P; where 'a' is the server side secret) 
	 * When used as a request header carries B (=g^b%P; where 'b'is the server side secret)
	 */
	static final String PUBLIC_KEY = "H-Public-Key";
	
	/**
	 * Custom HttPake header containing the subject confirmation.
	 * Subject confirmation is carried by all authenticated requests and responses.
	 * This header is also present in unauthenticated responses carrying the {@link #PUBLIC_KEY} header. 
	 * The subject confirmation is of the following format  "${requestOrResponseId}_${sessionId}_${nonce}" 
	 */
	static final String SUBJECT_CONFIRMATION = "H-Subject-Confirmation";
	
	/**
	 * Contains the subject signature, present in all authenticated requests and responses.
	 * When used as a request header the signing text is: {@link SubjectConfirmation} request-header value prefixed by {@link Constants#CLIENT_SIGNATURE_PREFIX}.
	 * When used as a response header the signing text is: {@link SubjectConfirmation} response-header value prefixed by {@link Constants#SERVER_SIGNATURE_PREFIX}.
	 * The header value is obtained by applying the following functions base64StringOf(HMAC-SHA256(signingText, httPakeKey))
	 */
	static final String SIGNATURE = "H-Signature";

}
