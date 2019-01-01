package org.hpake.protocol;

/**
 * Definitions for various constants used by HttPake. 
 * @author Wiraj Bibile
 *
 */
public interface Constants 
{
	/**
	 * Name of the authentication scheme.
	 */
	public static final String SCHEME = "Httpake1-0";
	
	/**
	 * Name of the identity password transform. 
	 * This maps the password to itself.
	 */
	public static final String TRANSFORM_IDENTITY = "identity";
	
	/**
	 * Name of the SHA256 transform.
	 * This maps the password to its SHA256 digest. 
	 */
	public static final String TRANSFORM_SHA256 = "sha256";
	
	/**
	 * HttPake prefix for data signed by the client.
	 * Format SIGN(prefix+data)
	 */
	public static final String CLIENT_SIGNATURE_PREFIX = "client-conf";
	
	/**
	 * HttPake prefix for data signed by the server. 
	 * Format SIGN(prefix+data)
	 */
	public static final String SERVER_SIGNATURE_PREFIX = "server-conf";
	
	/**
	 * How many request IDs to remember. 
	 * This value would depend on the maximum number of concurrent request the server is expected to server.
	 */
	public static final int REQUEST_ID_BUFFER_SIZE = 1000; 
	
}
