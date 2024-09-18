package ogs.switchon.common.communication.http;

import java.io.Serializable;

/**
 * Connection properties containers
 */
@SuppressWarnings("serial")
public class ConnectionBean implements Serializable {

	/**
	 * Host Name
	 */
	private transient String domainName;
	/**
	 * Content(Body) Type
	 */
	private final String contentType;
	/**
	 * Unique Id for log reference
	 */
	private final String logId;
	/**
	 * Log file token
	 */
	private final String logToken;
	/**
	 * URL's application name
	 */
	private transient String applicationName;
	/**
	 * URL's Version number
	 */
	private final String versionNo;
	/**
	 * URL's token services
	 */
	private final String tokenServices;	
	/**
	 * URL's Service path
	 */
	private final String servicePath;
	/**
	 * Connection auth's user name
	 */
	private final String username;
	/**
	 * Connection auth's password
	 */
	private final String password;
	/**
	 * Connection Custom header for all the message
	 */
	private String customeHeader;
	/**
	 * Connection's SSL key alias
	 */
	private final String aliasName;
	/**
	 * Connection's SSL key store password encrypted
	 */
	private final String keyStorePassword;
	/**
	 * Connection's SSL key store path
	 */
	private final String keyStoreFileName;
	/**
	 * Additional Url Params
	 */
	private final String additionalUrlParams;

	/**
	 * @param domainName       host name
	 * @param contentType      content/body type
	 * @param logId            log unique reference
	 * @param logToken         log file's token
	 * @param applicationName  application name of URL
	 * @param versionNo        version number of URL
	 * @param tokenServices    token services
	 * @param servicePath      service path
	 * @param username         user's name
	 * @param password         password
	 * @param token            generated token
	 * @param customeHeader    custom header for outgoing messages
	 * @param aliasName        alias of SSL key
	 * @param keyStorePassword SSL key store password
	 * @param keyStoreFileName SSL Key store file name
	 */
	public ConnectionBean(final String domainName, final String contentType, final String logId, final String logToken,
			final String applicationName, final String versionNo, final String tokenServices, final String servicePath,
			final String username, final String password, final String customeHeader, final String aliasName,
			final String keyStorePassword, final String keyStoreFileName) {
		super();
		this.domainName = domainName;
		this.contentType = contentType;
		this.logId = logId;
		this.logToken = logToken;
		this.applicationName = applicationName;
		this.versionNo = versionNo != null ? versionNo.trim() : versionNo;
		this.tokenServices = tokenServices;
		this.servicePath = servicePath;
		this.username = username;
		this.password = password;
		this.customeHeader = customeHeader;
		this.aliasName = aliasName;
		this.keyStorePassword = keyStorePassword;
		this.keyStoreFileName = keyStoreFileName;
		this.additionalUrlParams = null;
	}
	/**
	 * @param domainName
	 * @param contentType
	 * @param logId
	 * @param logToken
	 * @param applicationName
	 * @param versionNo
	 * @param tokenServices
	 * @param servicePath
	 * @param username
	 * @param password
	 * @param customeHeader
	 * @param aliasName
	 * @param keyStorePassword
	 * @param keyStoreFileName
	 * @param additionalUrlParams
	 */
	public ConnectionBean(final String domainName, final String contentType, final String logId, final String logToken,
			final String applicationName, final String versionNo, final String tokenServices, final String servicePath,
			final String username, final String password, final String customeHeader, final String aliasName,
			final String keyStorePassword, final String keyStoreFileName, final String additionalUrlParams) {
		super();
		this.domainName = domainName;
		this.contentType = contentType;
		this.logId = logId;
		this.logToken = logToken;
		this.applicationName = applicationName;
		this.versionNo = versionNo;
		this.tokenServices = tokenServices;
		this.servicePath = servicePath;
		this.username = username;
		this.password = password;
		this.customeHeader = customeHeader;
		this.aliasName = aliasName;
		this.keyStorePassword = keyStorePassword;
		this.keyStoreFileName = keyStoreFileName;
		this.additionalUrlParams = additionalUrlParams;
	}
	/**
	 * @return the domainName
	 */
	public String getDomainName() {
		return domainName;
	}
	
	/**
	 * Set the domainName
	 */
	public void setDomainName(final String domainName) {
		this.domainName = domainName;
	}

	/**
	 * @return the contentType
	 */
	public String getContentType() {
		return contentType;
	}

	/**
	 * @return the logId
	 */
	public String getLogId() {
		return logId;
	}

	/**
	 * @return the logToken
	 */
	public String getLogToken() {
		return logToken;
	}

	/**
	 * @return the applicationName
	 */
	public String getApplicationName() {
		return applicationName;
	}
	
	/**
	 * Set the applicationName
	 */
	public void setApplicationName(final String applicationName) {
		this.applicationName = applicationName;
	}

	/**
	 * @return the versionNo
	 */
	public String getVersionNo() {
		return versionNo;
	}

	/**
	 * @return the servicePath
	 */
	public String getServicePath() {
		return servicePath;
	}

	/**
	 * @return the username
	 */
	public String getUsername() {
		return username;
	}

	/**
	 * @return the password
	 */
	public String getPassword() {
		return password;
	}

	/**
	 * @return the customeHeader
	 */
	public String getCustomeHeader() {
		return customeHeader;
	}

	/**
	 * @return the aliasName
	 */
	public String getAliasName() {
		return aliasName;
	}

	/**
	 * @return the keyStorePassword
	 */
	public String getKeyStorePassword() {
		return keyStorePassword;
	}

	/**
	 * @return the keyStoreFileName
	 */
	public String getKeyStoreFileName() {
		return keyStoreFileName;
	}
	/**
	 * @return the tokenServices
	 */
	public String getTokenServices() {
		return tokenServices;
	}
	/**
	 * @return the additionalUrlParams
	 */	
	public String getAdditionalUrlParams() {
		return additionalUrlParams;
	}
	/**
	 * @param customheaders
	 */
	public void   setCustomeHeader( final String customheaders)
	{
		this.customeHeader=customheaders;
		
	}
}
