package ogs.switchon.common.communication.http;

import ogs.switchon.common.communication.http.constants.ProtocolType;
public class SslParamsBean {

	/**
	 * keyAlias
	 */
	private String keyAlias;
	/**
	 * skipCertVerify
	 */
	private boolean skipCertVerify;
	/**
	 * protocolType
	 */
	private ProtocolType protocolType;

	/**
	 * 
	 */
	public SslParamsBean() {
		super();
	}

	/**
	 * @param keyAlias
	 * @param skipCertVerify
	 * @param protocolType
	 */
	public SslParamsBean(final String keyAlias,final boolean skipCertVerify,final ProtocolType protocolType) {
		super();
		this.keyAlias = keyAlias;
		this.skipCertVerify = skipCertVerify;
		this.protocolType = protocolType;
	}

	/**
	 * @return the keyAlias
	 */
	public String getKeyAlias() {
		return keyAlias;
	}

	/**
	 * @param keyAlias the keyAlias to set
	 */
	public void setKeyAlias(String keyAlias) {
		this.keyAlias = keyAlias;
	}

	/**
	 * @return the skipCertVerify
	 */
	public boolean isSkipCertVerify() {
		return skipCertVerify;
	}

	/**
	 * @param skipCertVerify the skipCertVerify to set
	 */
	public void setSkipCertVerify(boolean skipCertVerify) {
		this.skipCertVerify = skipCertVerify;
	}

	/**
	 * @return the protocolType
	 */
	public ProtocolType getProtocolType() {
		return protocolType;
	}

}
