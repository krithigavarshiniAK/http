package ogs.switchon.common.communication.http.constants;

/**
 * 
 * @author Gowtham Aug 22, 2019
 *         ======================================================================================
 *         This Module contains Proprietary Information of OGS Paylab Pvt ltd.,
 *         and should be treated as Confidential. SwitchOn� is a registered
 *         trademarks of OGS Paylab Pvt Ltd.
 * 
 *         Copyright (C)2008-2011 OGS Paylab pvt ltd. All Rights Reserved
 * 
 *         This Is Unpublished Proprietary Source Code Of OGS Paylab Pvt Ltd.
 * 
 *         The copyright notice above does not evidence any actual or intended
 *         publication of such Source code.
 *         ======================================================================================
 *         Class Description :- Enum class will define the URL/API protocol type
 *         list
 *         ======================================================================================
 *         MODIFICATION HISTORY
 *
 *         DeveloperName Purpose/Reason ModifiedDate
 *         ---------------------------------------------------------------------------------------
 */
public enum ProtocolType {
	HTTP("http://"), HTTPS("https://");
	/**
	 * URL Protocol
	 */
	private final String protocol;

	/**
	 * Constructor
	 * 
	 * @param protocolType HTTP URL Protocol
	 */
	ProtocolType(final String protocolType) {
		this.protocol = protocolType;
	}

	/**
	 * 
	 * <p>
	 * HTTP Protocol prefix producer
	 * </p>
	 * 
	 * @param isSSLEnabled SSL flag
	 * @return HTTP with prefix
	 */
	public static ProtocolType geProtocolType(final boolean isSSLEnabled) {
		ProtocolType type;
		if (isSSLEnabled)
			type = HTTPS;
		else
			type = HTTP;
		return type;
	}

	public String getProtocol() {
		return protocol;
	}
}
