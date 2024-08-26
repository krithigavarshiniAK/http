/**
 * <B><I>Copyright (C)2019-2029 OGS Paylab pvt ltd. All Rights Reserved</I></B><BR><BR>
 * <p>
 * This Is Unpublished Proprietary Source Code Of OGS Paylab Pvt Ltd.
 * 
 * The copyright notice above does not evidence any actual or intended
 * publication of such Source code.
 * </p>
 **/
package ogs.switchon.common.communication.http.exception;

import java.io.IOException;

/**
 * ======================================================================================
 * <BR>
 * Class Description :-<BR>
 * <p>
 * Purpose of this class and List of methods and its usage.
 * </p>
 * ======================================================================================
 * <BR>
 * <B><I>MODIFICATION HISTORY</I></B><BR>
 * <BR>
 *
 * <I>DeveloperName Purpose/Reason ModifiedDate</I><BR>
 * ---------------------------------------------------------------------------------------
 * <BR>
 **/
@SuppressWarnings("serial")
public class SSLFailureException extends IOException {

	/**
	 * Uses the application tries to trigger forcefully
	 * 
	 * @param message reason of the exception
	 */
	public SSLFailureException(final String message) {
		super(message);
	}

	/**
	 * Thrown using the other exception along with root cause
	 * 
	 * @param message reason of the exception
	 * @param cause   root cause
	 */
	public SSLFailureException(final String message, final Throwable cause) {
		super(message, cause);
	}

}
