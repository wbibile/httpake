package org.hpake.examples.client;

/**
 * An interface for retrieving credentials.
 */
public interface UserCredentialInput 
{
	
	
	/**
	 * Gets the password.
	 * @return the password.
	 */
	public char[] getPassword();
	
	/**
	 * @return The user name
	 */
	public String getUserName();
}
