package ogs.switchon.common.communication.http;

/**
 * @author Manojkumar .N
 * Token bean is for processing token related additional url parameters and credentials in it 
 *
 */
public class TokenBean {

	/**
	 * Unique identifier for the URL
	 */
	private Integer urlId;
	
	/**
	 * Domain name of the URL
	 */
	private String domainName;
	/**
	 * Application name of the URL
	 */
	private String appName;

	/**
	 * Version number
	 */
	private String versionNo;
	/**
	 * Service's url path
	 */
	private String servicePath;
	/**
	 * HTTP Method type
	 */
	private Integer methodType;
	/**
	 * Authorization type
	 */
	private Integer authType;
	/**
	 * Authorization reference id
	 */
	private Integer authRefId;
	/**
	 * URL Type, whether SSL or plain
	 */
	private Boolean urlType;

	/**
	 * additionalTokenParams
	 */
	private String additionalTokenParams;

	/**
	 * AdditionalTokenUrlParams
	 */
	private String additionalTokenUrlParams;

	/**
	 * @return url id
	 */
	public Integer getUrlId() {
		return urlId;
	}
	/**
	 * @param urlId
	 */
	public void setUrlId(final Integer urlId) {
		this.urlId = urlId;
	}
	/**
	 * @return domain name 
	 */
	public String getDomainName() {
		return domainName;
	}
	/**
	 * @param domainName
	 */
	public void setDomainName(final String domainName) {
		this.domainName = domainName;
	}
	/**
	 * @return appName for token request 
	 */
	public String getAppName() {
		return appName;
	}
	/**
	 * @param appName
	 */
	public void setAppName(final String appName) {
		this.appName = appName;
	}

	/**
	 * @return version no 
	 */
	public String getVersionNo() {
		return versionNo;
	}
	/**
	 * @param versionNo
	 */
	public void setVersionNo(final String versionNo) {
		this.versionNo = versionNo;
	}
	/**
	 * @return service path for token request
	 */
	public String getServicePath() {
		return servicePath;
	}
	/**
	 * @param servicePath 
	 */
	public void setServicePath(final String servicePath) {
		this.servicePath = servicePath;
	}
	/**
	 * @return methodType
	 */
	public Integer getMethodType() {
		return methodType;
	}
	/**
	 * @param methodType
	 */
	public void setMethodType(final Integer methodType) {
		this.methodType = methodType;
	}
	/**
	 * @return auth type
	 */
	public Integer getAuthType() {
		return authType;
	}
	/**
	 * @param authType
	 */
	public void setAuthType(final Integer authType) {
		this.authType = authType;
	}
	/**
	 * @return authRefId
	 */
	public Integer getAuthRefId() {
		return authRefId;
	}
	/**
	 * @param authRefId
	 */
	public void setAuthRefId(final Integer authRefId) {
		this.authRefId = authRefId;
	}
	/**
	 * @return urlType
	 */
	public Boolean getUrlType() {
		return urlType;
	}
	/**
	 * @param urlType
	 */
	public void setUrlType(final Boolean urlType) {
		this.urlType = urlType;
	}
	/**
	 * @return additionalTokenParams
	 */
	public String getAdditionalTokenParams() {
		return additionalTokenParams;
	}
	/**
	 * @param additionalTokenParams
	 */
	public void setAdditionalTokenParams(final String additionalTokenParams) {
		this.additionalTokenParams = additionalTokenParams;
	}
	/**
	 * @return additionalTokenUrlParams
	 */
	public String getAdditionalTokenUrlParams() {
		return additionalTokenUrlParams;
	}
	/**
	 * @param additionalTokenUrlParams
	 */
	public void setAdditionalTokenUrlParams(final String additionalTokenUrlParams) {
		this.additionalTokenUrlParams = additionalTokenUrlParams;
	}

}
