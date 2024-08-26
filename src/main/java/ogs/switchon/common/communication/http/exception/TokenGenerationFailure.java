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
public class TokenGenerationFailure extends IOException {

	/**
	 * @param message reason of the exception
	 */
	public TokenGenerationFailure(final String message) {
		super(message);
	}

	/**
	 * Used to trigger by other exception with root cause
	 * 
	 * @param message reason of the exception
	 * @param cause   root cause
	 */
	public TokenGenerationFailure(final String message, final Throwable cause) {
		super(message, cause);
	}

}
