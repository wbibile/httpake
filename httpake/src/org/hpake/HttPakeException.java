package org.hpake;

/**
 * HttPake Exception
 * @author Wiraj Bibile
 */
public class HttPakeException extends RuntimeException
{
    private static final long serialVersionUID = 1L;
    
    private boolean serverError; 
    
	public HttPakeException() 
	{
		super();
	}

	/**
	 * @param cause The cause
	 */
	public HttPakeException(Throwable cause) 
	{
		super(cause);
	}

	/**
	 * @param message The exception message
	 * @param cause the cause
	 */
	public HttPakeException(String message, Throwable cause) 
	{
		super(message, cause);
	}

	/**
	 * @param message Exception message
	 */
	public HttPakeException(String message) 
	{
		super(message);
	}

	/**
	 * Make this exception as being caused by a server error.
	 * @return this instance
	 */
	public HttPakeException setAsServerError()
	{
		this.serverError = true;
		return this;
	}

	/**
	 * @return true if the error is a server error
	 */
	public boolean isServerError()
	{
		return serverError;
	}

}
