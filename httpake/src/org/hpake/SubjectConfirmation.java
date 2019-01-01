package org.hpake;

import java.math.BigInteger;

import org.hpake.protocol.Constants;
import org.hpake.protocol.Headers;

/**
 * Instances of this class represents HttPake subject confirmation.
 * The subject confirmation encapsulates the request ID, session ID and, nonce.
 * The subject confirmation string is unique for a request or response when, combined with a prefix ({@link Constants#SERVER_SIGNATURE_PREFIX} or
 * {@link Constants#CLIENT_SIGNATURE_PREFIX}). This unique string is signed to produce the request or response signature.
 */
public class SubjectConfirmation 
{
	private final String sessionId;
	private final String nonce;
	private final String serializationString;
	private final BigInteger requestOrResponseId;
	
	/**
	 * Create a new instance using constituent parts. 
	 * @param requestOrResponseId the request or response ID
	 * @param sessionId session ID
	 * @param nonce confirmation string nonce
	 * @return the new instance 
	 */
	public static SubjectConfirmation newInstance(long requestOrResponseId, String sessionId, String nonce) 
	{
		return newInstance(BigInteger.valueOf(requestOrResponseId), sessionId, nonce);
	}
	
	/**
	 * Create a new instance using constituent parts. 
	 * @param requestOrResponseId the request or response ID
	 * @param sessionId session ID
	 * @param nonce confirmation string nonce
	 * @return the newly created instance 
	 */
	public static  SubjectConfirmation newInstance(BigInteger requestOrResponseId, String sessionId, String nonce) 
	{
		String serializationString =  requestOrResponseId.toString(16)+Utils.VALUE_SEPARATOR+sessionId+Utils.VALUE_SEPARATOR+nonce;
		return new SubjectConfirmation(serializationString, requestOrResponseId, sessionId, nonce);
	}
	
	/**
	 * Creates a new instance from the value of a {@link Headers#SUBJECT_CONFIRMATION} header (serialization string).
	 * @param serializationString Value of the subject confirmation header
	 * @return newly created instance
	 */
	public static SubjectConfirmation newInstance(String serializationString) throws HttPakeException
	{
		String[] parts = Utils.VALUE_SEPARATOR_PATTERN.split(serializationString, 3);
		if(parts.length != 3)
		{
			throw createFormatException();
		}
		BigInteger requestOrResponseId;
		try 
		{
			requestOrResponseId = new BigInteger(parts[0], 16);
		}
		catch (NumberFormatException e) 
		{
			throw createFormatException();
		}
		return new SubjectConfirmation(serializationString, requestOrResponseId, parts[1], parts[2]);
	}
	
	private static HttPakeException createFormatException()
	{
		return new HttPakeException("Invalid subject confirmation.");
	}
	
	/**
	 * The value of the {@link Headers#SUBJECT_CONFIRMATION} HTTP header. 
	 * @return The header text
	 */
	public String getHeaderValue()
	{
		return serializationString;
	}
	
	private SubjectConfirmation(String serializationString, BigInteger requestResponseId, String sessionId, String nonce)
	{
		this.requestOrResponseId = requestResponseId;
		this.sessionId = sessionId;
		this.nonce = nonce;
		this.serializationString = serializationString;
	}
	
	private SubjectConfirmation(String serializationString, long requestResponseId, String sessionId, String nonce)
	{
		this(serializationString,  BigInteger.valueOf(requestResponseId), sessionId, nonce);
	}
	
	
	/**
	 * The value of the response header {@link Headers#SIGNATURE}
	 * @param key Signing key
	 * @return The server signature
	 */
	public String serverSignature(byte[] key, int statusCode) throws HttPakeException
	{
		assert(statusCode >= 100 && statusCode <1000):"Invalid status code "+statusCode;
		return Utils.signText(key, Constants.SERVER_SIGNATURE_PREFIX+Integer.toString(statusCode)+serializationString);
	}

	/**
	 * The value of the request header {@link Headers#SIGNATURE}.
	 * Format: 
	 * @param key Signing key
	 * @return The client signature
	 */
	public String getClientSignature(byte[] key) throws HttPakeException
	{
		return Utils.signText(key, Constants.CLIENT_SIGNATURE_PREFIX+serializationString);
	}
	
	@Override
	public String toString()
	{
		return getHeaderValue();
	}

	/**
	 * @return The request or response ID
	 */
	public BigInteger getRequestOrResponseId() 
	{
		return requestOrResponseId;
	}

	/**
	 * @return The session ID
	 */
	public String getSessionId()
	{
		return sessionId;
	}

	/**
	 * @return The subject confirmation nonce
	 */
	public String getNonce()
	{
		return nonce;
	}
}
