package ogs.switchon.common.communication.http;

import com.fasterxml.jackson.databind.ObjectMapper;
import ogs.switchon.common.communication.http.constants.HTTPConstants;
import ogs.switchon.common.communication.http.constants.MethodType;
import ogs.switchon.common.communication.http.constants.ProtocolType;
import ogs.switchon.common.communication.http.utils.HttpConnectionHandler;
import ogs.switchon.common.modules.communication.BaseTransactionBlockingQueue;
import ogs.switchon.common.modules.communication.MessageBean;
import ogs.switchon.common.modules.security.SslHelper;
import ogs.switchon.common.shared.ApplicationData;
import ogs.switchon.common.utilities.ApplicationUtils;
import ogs.switchon.common.utilities.ByteUtils;
import org.springframework.util.StringUtils;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This bean class is derived class of httpclient and it will hold
 * single URL information. The basic operation handled in this method is: -
 * openConnection() - This method will create a connection and holds the input
 * and output streams.
 */

public class ConnectionHandler extends HttpConnectionHandler {
    /**
     * Class name for the log
     */
    private static final String CLASSNAME = ApplicationUtils.formatClassName("URL");

    /**
     * HTTP/HTTPS Token cache hash map
     */
    public static ConcurrentMap<String, Object> authTokenData = new ConcurrentHashMap<>();

    /**
     * Connection properties bean
     */
    private final ConnectionBean connectionBean;

    /**
     * Token generated time
     */
    private Long tokenGenerateTime;

    /**
     * Token expiry period
     */
    private final int tokenExpirePeriod;

    /**
     * Auth type
     */
    private final int authType;

    /**
     * Character encoder
     */
    private final CharsetEncoder encoder = Charset.forName("UTF-8").newEncoder();

    /**
     * HTTP Method type
     */
    private final MethodType methodType;

    /**
     * HTTP Protocol type
     */
    private transient ProtocolType protocolType;

    /**
     * Response time out in seconds
     */
    private final int responseTimeOut;

    /**
     * Connection time out in seconds
     */
    private final int connectionTimeOut;

    /**
     * Used in full url method
     */
    private static Integer connection_TimeOut = 10_000;

    /**
     * used in full url method
     */
//	private static Integer response_TimeOut = 30_000;

    /**
     * Queue object
     */
    private final BaseTransactionBlockingQueue queue;

    /**
     * HTTP Constant
     */
    private static final String HTTP_CONST = "http:";

    /**
     * Return object
     */
    private final Object retObject;

    /**
     * Skip Certificate verification value
     */
    private final boolean skipCertVerify;

    /**
     * Token services bean
     */
    private TokenBean tokenServicesBean;

    /**
     * isStatusCodeRequired
     */
    private boolean isStatusCodeRequired = false;

    /**
     * Bearer token string appending
     */
    private static final String BEARER_TAG = "Bearer ";

    /**
     * ObjectMapper
     */
    private final static ObjectMapper OBJ_MAPPER = new ObjectMapper();

    /**
     * client initialization
     */
    private final HttpClient httpClient = HttpClient.newHttpClient();

    public ConnectionHandler(ConnectionBean connectionBean, int tokenExpirePeriod, int authType,
                             MethodType methodType, int responseTimeOut, int connectionTimeOut,
                             BaseTransactionBlockingQueue queue, Object retObject, boolean skipCertVerify) {
        this.connectionBean = connectionBean;
        this.tokenExpirePeriod = tokenExpirePeriod;
        this.authType = authType;
        this.methodType = methodType;
        this.responseTimeOut = responseTimeOut;
        this.connectionTimeOut = connectionTimeOut;
        this.queue = queue;
        this.retObject = retObject;
        this.skipCertVerify = skipCertVerify;
    }

    /**
     * The constructor to used for creating connection with all parameter
     *
     * @param domainName            URL Domain name either IPAddress and Port or API
     *                              URL
     * @param contentType           Message Content Type for both Read/Write
     *                              function
     * @param methodType            Which method category to use this URL
     * @param protocolType          Identify the URL protocol type either HTTP or
     *                              HTTPS
     * @param aliasName             SSL certificate alias name
     * @param keyStorePassword      SSL key store encoded password
     * @param keyStoreFileName      SSL key store file name
     * @param appName               Application name
     * @param versionNo             Application version number.
     * @param services              API services path definition with Version no
     * @param responseTimeOut       Response Time out seconds
     * @param connectionTimeOut     Connection time out in seconds
     * @param username              If the basic auth type means username is
     *                              mandatory
     * @param password              If the basic auth type means password is
     *                              mandatory
     * @param logId                 Logger Id
     * @param logToken              Logger Token
     * @param tokenServices         Token service path definition
     * @param authType              HTTP Authentication category type 0 as NoAuth, 1
     *                              as Token validation, 2 as username and password
     * @param lastTokenGenerateTime Last Token Generated Time in milliseconds.
     * @param expiryTime            Token Expire time interval in seconds.
     * @param customeHeader         custom header of the api call
     */
    public ConnectionHandler(final String domainName, final String contentType, final Integer methodType,
                             final boolean protocolType, final String aliasName, final String keyStorePassword,
                             final String keyStoreFileName, final String appName, final String versionNo, final String services,
                             final Integer responseTimeOut, final Integer connectionTimeOut, final String username,
                             final String password, final String logId, final String logToken, final String tokenServices,
                             final Integer authType, final Long lastTokenGenerateTime, final Integer expiryTime,
                             final String customeHeader, final BaseTransactionBlockingQueue queue, final Object retObject,
                             final boolean skipCertVerify) {
        super();
        if (aliasName == null)
            disableSslVerification();
        connectionBean = new ConnectionBean(domainName, contentType, logId, logToken, appName, versionNo, tokenServices,
                services, username, password, customeHeader, aliasName, keyStorePassword, keyStoreFileName);
        this.methodType = MethodType.getMethodType(methodType);
        this.protocolType = ProtocolType.geProtocolType(protocolType);
        this.responseTimeOut = responseTimeOut * 1000;
        this.connectionTimeOut = connectionTimeOut * 1000;
        this.tokenExpirePeriod = expiryTime;
        this.tokenGenerateTime = lastTokenGenerateTime;
        this.authType = authType;
        this.queue = queue;
        this.retObject = retObject;
        this.skipCertVerify = skipCertVerify;
    }

    /**
     * @param domainName
     * @param contentType
     * @param methodType
     * @param protocolType
     * @param aliasName
     * @param keyStorePassword
     * @param keyStoreFileName
     * @param appName
     * @param versionNo
     * @param services
     * @param responseTimeOut
     * @param connectionTimeOut
     * @param username
     * @param password
     * @param additionalUrlParams
     * @param logId
     * @param logToken
     * @param tokenServices
     * @param authType
     * @param lastTokenGenerateTime
     * @param expiryTime
     * @param customeHeader
     * @param queue
     * @param retObject
     * @param skipCertVerify
     */
    public ConnectionHandler(final String domainName, final String contentType, final Integer methodType,
                             final boolean protocolType, final String aliasName, final String keyStorePassword,
                             final String keyStoreFileName, final String appName, final String versionNo, final String services,
                             final Integer responseTimeOut, final Integer connectionTimeOut, final String username,
                             final String password, final String additionalUrlParams, final String logId, final String logToken,
                             final String tokenServices, final Integer authType, final Long lastTokenGenerateTime,
                             final Integer expiryTime, final String customeHeader, final BaseTransactionBlockingQueue queue,
                             final Object retObject, final boolean skipCertVerify) {
        super();
        if (aliasName == null)
            disableSslVerification();
        connectionBean = new ConnectionBean(domainName, contentType, logId, logToken, appName, versionNo, tokenServices,
                services, username, password, customeHeader, aliasName, keyStorePassword, keyStoreFileName,
                additionalUrlParams);
        this.methodType = MethodType.getMethodType(methodType);
        this.protocolType = ProtocolType.geProtocolType(protocolType);
        this.responseTimeOut = responseTimeOut * 1000;
        this.connectionTimeOut = connectionTimeOut * 1000;
        this.tokenExpirePeriod = expiryTime;
        this.tokenGenerateTime = lastTokenGenerateTime;
        this.authType = authType;
        this.queue = queue;
        this.retObject = retObject;
        this.skipCertVerify = skipCertVerify;
    }

    /**
     * This method will create new httpclient connection using URL or API with respected
     * domainName
     *
     */
    private HttpRequest.Builder startConnect(final String logToken, final ApplicationData appData) throws IOException, InterruptedException {

        logger.info(this.connectionBean.getLogId() + " Initiate URL Connection " + this.connectionBean.getDomainName(),
                CLASSNAME, logToken);
        String locUrlPath = null;
        String additionalUrlParams = this.connectionBean.getAdditionalUrlParams();
        final StringBuilder stringBuilder = new StringBuilder();
        if (this.connectionBean.getApplicationName() != null && !this.connectionBean.getApplicationName().isEmpty()) {
            stringBuilder.append(this.connectionBean.getApplicationName() + HTTPConstants.SEPARATOR.value());
        }
        if (this.connectionBean.getVersionNo() != null && !this.connectionBean.getVersionNo().isEmpty()) {
            stringBuilder.append(this.connectionBean.getVersionNo() + HTTPConstants.SEPARATOR.value());
        }
        if (this.connectionBean.getServicePath() != null && !this.connectionBean.getServicePath().isEmpty()) {
            stringBuilder.append(this.connectionBean.getServicePath());
        }
        if (additionalUrlParams != null) {
            additionalUrlParams = assignDefaultSwitchvariables(additionalUrlParams, appData);
            stringBuilder.append(additionalUrlParams);
        }
        locUrlPath = stringBuilder.toString();
        locUrlPath = replaceAppVariables(locUrlPath, appData);

        return OpenConnection(this.connectionBean.getDomainName(), protocolType, locUrlPath);
    }

    /**
     * Construct url by replacing if app variables present for dynamic url
     * constructions
     *
     */
    public String replaceAppVariables(final String urlPath, final ApplicationData paramAppData) {
        String url = urlPath;
        final Pattern pattern = Pattern.compile("\\{([^\\\"]{0,4})\\}");
        final Matcher matcher = pattern.matcher(url);
        while (matcher.find()) {
            url = url.replace(matcher.group(),
                    paramAppData.getFromNonSensitiveAppData(Integer.parseInt(matcher.group(1))));
        }
        return url;
    }

    /**
     * @param defaultValues
     * @param appData
     */
    public String assignDefaultSwitchvariables(final String defaultValues, final ApplicationData appData) {
        String[] keyValuePairs = null;
        String[] pairs = null;
        String finalUrl = null;
        final StringBuffer additionalUrl = new StringBuffer();
        try {
            additionalUrl.append('?');
            keyValuePairs = defaultValues.split(",");
            for (final String pair : keyValuePairs) {
                pairs = pair.split("=");
                additionalUrl.append(pairs[0]).append('=')
                        .append(appData.getFromNonSensitiveAppData(Integer.parseInt(pairs[1]))).append('&');
            }
            finalUrl = additionalUrl.substring(0, additionalUrl.length() - 1);
            keyValuePairs = null;
            pairs = null;
        } catch (ArrayIndexOutOfBoundsException | NumberFormatException e) {
            logger.error(this.connectionBean.getLogId() + "Exception in setDefaultSwitchvariables method", CLASSNAME,
                    this.connectionBean.getLogToken());
        }
        return finalUrl;
    }

    /**
     *
     * @param logToken
     * @param dataBytes
     * @param token
     * @param appData
     * @param additionalFields
     * @return
     * @throws Exception
     */
    public byte[] doRequest(final String logToken, final byte[] dataBytes, final String token, final ApplicationData appData,
                            final Object additionalFields) throws Exception {

        byte[] responseBytes;
        final ObjectMapper objectMapper = new ObjectMapper();
        final SslParamsBean sslParamsBean = new SslParamsBean();

        HttpRequest.Builder originalRequest = startConnect(logToken, appData);
        String additionalFieldStr = (additionalFields instanceof String) ? (String) additionalFields : "";
        HttpRequest httpRequest = initiateConnection(originalRequest, ByteUtils.copyBytesAsString(dataBytes, 0),  additionalFieldStr);
        logger.info(this.connectionBean.getLogId() + " URL for Connecting " + originalRequest, CLASSNAME, logToken);

        if (sslParamsBean.getProtocolType() == ProtocolType.HTTPS) {
            HttpClient httpsClient = httpClientWithSSL(sslParamsBean);
            responseBytes = writeAndRead(httpsClient, httpRequest, dataBytes, logToken, token, objectMapper);
        } else {
            responseBytes = writeAndRead(httpClient, httpRequest, dataBytes, logToken, token, objectMapper);
        }

        responseQueueProcess(dataBytes);

        return responseBytes;
    }

    /**
     *
     * @param dataBytes
     * @param token
     * @param appData
     * @param additionalFields
     * @param additionalTokenFields
     * @return
     * @throws Exception
     */
    public byte[] doRequest(final byte[] dataBytes, final String token, final ApplicationData appData,
                            final Object additionalFields, final Object additionalTokenFields) throws Exception {
        byte[] responseBytes;
        final ObjectMapper objectMapper = new ObjectMapper();
        final SslParamsBean sslParamsBean = new SslParamsBean();

        HttpRequest.Builder originalRequest = startConnect(this.connectionBean.getLogToken(), appData);
        String additionalFieldStr = (additionalFields instanceof String) ? (String) additionalFields : "";
        String additionalTokenFieldStr = (additionalTokenFields instanceof String) ? (String) additionalTokenFields : "";

        HttpRequest httpRequest = initiateConnection(originalRequest, ByteUtils.copyBytesAsString(dataBytes, 0), additionalTokenFieldStr);
        logger.info(this.connectionBean.getLogId() + " URL for Connecting " + originalRequest, CLASSNAME, this.connectionBean.getLogToken());

        if (sslParamsBean.getProtocolType() == ProtocolType.HTTPS) {
            HttpClient httpsClient = httpClientWithSSL(sslParamsBean);
            responseBytes = writeAndRead(httpsClient, httpRequest, dataBytes, this.connectionBean.getLogToken(), token, objectMapper);
        } else {
            responseBytes = writeAndRead(httpClient, httpRequest, dataBytes, this.connectionBean.getLogToken(), token, objectMapper);
        }
        responseQueueProcess(dataBytes);

        return responseBytes;
    }


    /**
     *
     * @param responseBytes
     */
    private void responseQueueProcess(final byte[] responseBytes) {
        if (this.queue != null) {
            final MessageBean messageBean = new MessageBean(this.connectionBean.getDomainName(), retObject,
                    responseBytes);
            this.queue.accept(messageBean);
        }
    }

    public HttpClient httpClientWithSSL(SslParamsBean sslParamsBean) throws Exception {
        HttpClient.Builder clientBuilder = HttpClient.newBuilder();
        if (sslParamsBean.getKeyAlias() != null && StringUtils.hasText(sslParamsBean.getKeyAlias())
                && sslParamsBean.getProtocolType() == ProtocolType.HTTPS) {
            SSLContext sslContext = SslHelper.loadSSLcertificate(sslParamsBean.getKeyAlias(), sslParamsBean.isSkipCertVerify());

            clientBuilder.sslContext(sslContext);
        }
        return clientBuilder.build();
    }

    /**
     * This method will load common default parameter for http client connection.
     * @param httpRequest
     * @param tokenMessageBytes
     * @param additionalTokenFields
     * @return
     * @throws IOException
     * @throws InterruptedException
     */
    private HttpRequest initiateConnection(final HttpRequest.Builder httpRequest, final String tokenMessageBytes,
                                                    final String additionalTokenFields) throws IOException, InterruptedException {

        if (methodType != null) {
            httpRequest.method(methodType.getMethodType(), HttpRequest.BodyPublishers.noBody());
        } else {
            httpRequest.GET();
        }

        if (this.connectionBean.getContentType() == null) {
            httpRequest.header(HTTPConstants.CONTENT_TYPE.value(), HTTPConstants.DEFUALT_CHARSET.value());
        } else {
            httpRequest.header(HTTPConstants.CONTENT_TYPE.value(), this.connectionBean.getContentType() + HTTPConstants.CHARSET.value())
                    .header(HTTPConstants.ACCEPT.value(), this.connectionBean.getContentType());
        }
        setHttpHeader(httpRequest, tokenMessageBytes, connectionBean.getLogId(), connectionBean.getLogToken(), additionalTokenFields);
        return httpRequest.build();
    }

    public HttpRequest.Builder setHttpHeader(final HttpRequest.Builder requestBuilder, final String tokenMessageBytes,
                                             final String msgId, final String logToken, final String additionalTokenFields) throws IOException {

        String token;
        if (this.connectionBean.getDomainName() != null) {
            token = (String) authTokenData.get(this.connectionBean.getDomainName());
            if (token != null) {
                tokenGenerateTime = (Long) authTokenData.get(token);
            }

            switch (authType) {
                case 1:
                    if (token == null || (System.currentTimeMillis() - tokenGenerateTime) > tokenExpirePeriod * 60 * 1000) {
                        token = super.generateToken(
                                protocolType,
                                this.connectionBean.getDomainName(),
                                this.connectionBean.getApplicationName(),
                                tokenServicesBean != null ? tokenServicesBean : connectionBean.getTokenServices(),
                                this.connectionBean.getUsername(),
                                this.connectionBean.getPassword(),
                                this.connectionBean.getVersionNo(),
                                methodType);

                        authTokenData.put(connectionBean.getDomainName(), token);
                        tokenGenerateTime = System.currentTimeMillis();
                    }
                    requestBuilder.header(HTTPConstants.AUTHORIZATION.value(), token);
                    break;

                case 2:
                    requestBuilder.header(HTTPConstants.USERNAME.value(), connectionBean.getUsername())
                            .header(HTTPConstants.PASSWORD.value(), connectionBean.getPassword());
                    break;

                case 3:
                    final Base64.Decoder decoder = Base64.getDecoder();
                    final String customHeader = new String(decoder.decode(connectionBean.getCustomeHeader()),
                            StandardCharsets.UTF_8);
                    final Map<String, String> headerMap = OBJ_MAPPER.readValue(customHeader, Map.class);
                    headerMap.forEach(requestBuilder::header);
                    break;

                case 4:
                    if (token == null || (System.currentTimeMillis() - tokenGenerateTime) > tokenExpirePeriod * 60 * 1000) {
                        token = super.generateOauthToken(
                                protocolType,
                                this.connectionBean.getDomainName(),
                                this.connectionBean.getApplicationName(),
                                tokenServicesBean != null ? tokenServicesBean : connectionBean.getTokenServices(),
                                this.connectionBean.getUsername(),
                                this.connectionBean.getPassword(),
                                this.connectionBean.getVersionNo(),
                                methodType,
                                tokenMessageBytes,
                                msgId,
                                logToken,
                                this.connectionBean.getAliasName(),
                                skipCertVerify);

                        authTokenData.put(connectionBean.getDomainName(), token);
                        tokenGenerateTime = System.currentTimeMillis();
                        authTokenData.put(token, tokenGenerateTime);
                    }
                    requestBuilder.header(HTTPConstants.AUTHORIZATION.value(), BEARER_TAG + token);
                    if (additionalTokenFields != null) {
                        HashMap<String, String> headersParams = OBJ_MAPPER.readValue(additionalTokenFields, HashMap.class);
                        headersParams.forEach(requestBuilder::header);
                    }
                    break;

                case 5:
                    final String credentials = connectionBean.getUsername() + ":" + connectionBean.getPassword();
                    final String authValue = Base64.getEncoder().encodeToString(credentials.getBytes());
                    requestBuilder.header(HTTPConstants.AUTHORIZATION.value(), "Basic " + authValue);
                    break;

                default:
                    break;
            }
        }

        return requestBuilder;
    }

    /**
     * Push or hit the given url with the secured protocol
     * @param messageBytes
     * @param fullUrl
     * @param method
     * @param headers
     * @param keyAlias
     * @param sslVerification
     * @return
     * @throws Exception
     */
    public byte[] pushSecuredRequest(final byte[] messageBytes, final String fullUrl, final MethodType method,
                                     final Map<String, String> headers, final String keyAlias, final boolean sslVerification) throws Exception {
        byte[] retBytes;
        if (fullUrl.startsWith("http") && protocolType == ProtocolType.HTTP) {
            retBytes = pushRequest(messageBytes, fullUrl, method, headers);
        } else {
            SslParamsBean sslParams = getSSLParams(keyAlias, sslVerification);
            String logToken = connectionBean.getLogToken();
            String logId = connectionBean.getLogId();

            retBytes = doRequest(logToken, messageBytes, logId, null, headers);
        }
        return retBytes;
    }

   /**
    * Push or hit the given url with the http insecured protocol
    */
    public byte[] pushRequest(final byte[] messageBytes, final String fullUrl, final MethodType method,
                              final Map<String, String> headers) throws Exception {
        byte[] retBytes;
        if (fullUrl.startsWith("https") && protocolType == ProtocolType.HTTPS) {
            retBytes = pushSecuredRequest(messageBytes, fullUrl, method, headers, null, true);
        } else {
            String logToken = connectionBean.getLogToken();
            String logId = connectionBean.getLogId();

            retBytes = doRequest(logToken, messageBytes, logId, null, headers);
        }
        return retBytes;
    }

    private SslParamsBean getSSLParams(String keyAlias, boolean sslVerification) {
        SslParamsBean sslParamsBean = new SslParamsBean();

        sslParamsBean.setKeyAlias(keyAlias);
        sslParamsBean.setSkipCertVerify(sslVerification);

        return sslParamsBean;
    }

    /**
     *
     * @returnskipCertVerify
     */
    public boolean isSkipCertVerify() {
        return skipCertVerify;
    }

    /**
     * tokenServicesBean
     *
     * @return
     */
    public TokenBean getTokenServicesBean() {
        return tokenServicesBean;
    }

    /**
     * setTokenServicesBean
     *
     * @param tokenServicesBean
     */
    public void setTokenServicesBean(final TokenBean tokenServicesBean) {
        this.tokenServicesBean = tokenServicesBean;
    }

    @SuppressWarnings({ "PMD.UseShortArrayInitializer", "PMD.ReturnEmptyArrayRatherThanNull",
            "PMD.UncommentedEmptyMethodBody", "PMD.MissingOverride", "PMD.EmptyCatchBlock" })
    static void disableSslVerification() {
        try {
            // Create a trust manager that does not validate certificate chains
            final TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
                /**
                 *
                 */
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                /**
                 *
                 */
                @Override
                public void checkClientTrusted(final X509Certificate[] arg0, final String arg1)
                        throws CertificateException {
                }

                /**
                 *
                 */
                @Override
                public void checkServerTrusted(final X509Certificate[] arg0, final String arg1)
                        throws CertificateException {
                }
            } };

            // Install the all-trusting trust manager
            final SSLContext sc = SSLContext.getInstance("TLSv1.2");
            sc.init(null, trustAllCerts, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Create all-trusting host name verifier
            final HostnameVerifier allHostsValid = new HostnameVerifier() {
                /**
                 *
                 */
                public boolean verify(final String hostname, final SSLSession session) {
                    return true;
                }
            };

            // Install the all-trusting host verifier
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {

        }
    }
}
