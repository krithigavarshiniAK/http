/**
 * <B><I>Copyright (C)2019-2029 OGS Paylab pvt ltd. All Rights Reserved</I></B><BR><BR>
 * <p>
 * This Is Unpublished Proprietary Source Code Of OGS Paylab Pvt Ltd.
 * 
 * The copyright notice above does not evidence any actual or intended
 * publication of such Source code.
 * </p>
 **/
package ogs.switchon.common.communication.http.constants;

/**
 * HTTP Constants
 **/
public enum HTTPConstants {

	SEPARATOR("/"), CONTENT_TYPE("Content-Type"), CHARSET("; charset=utf-8"), DEFUALT_CHARSET("application/json"),
	USERNAME("username"), PASSWORD("password"), ACCEPT("Accept"), AUTHORIZATION("Authorization"),
	URLENCODED("application/x-www-form-urlencoded"),;

	/**
	 * Value of the property
	 */
	private String value;

	HTTPConstants(final String value) {
		this.value = value;
	}

	/**
	 * 
	 * @return property's value
	 */
	public String value() {
		return this.value;
	}
}
