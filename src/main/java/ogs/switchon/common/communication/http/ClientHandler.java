package ogs.switchon.common.communication.http;

import com.fasterxml.jackson.databind.ObjectMapper;
import ogs.switchon.common.communication.http.constants.HTTPConstants;
import ogs.switchon.common.communication.http.constants.MethodType;
import ogs.switchon.common.communication.http.constants.ProtocolType;
import ogs.switchon.common.communication.http.utils.HttpClientHandler;
import ogs.switchon.common.exceptions.InvalidBufferStream;
import ogs.switchon.common.exceptions.SocketClosedException;
import ogs.switchon.common.modules.communication.BaseTransactionBlockingQueue;
import ogs.switchon.common.modules.security.SslHelper;
import ogs.switchon.common.shared.ApplicationData;
import ogs.switchon.common.utilities.ApplicationUtils;
import org.springframework.util.StringUtils;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URLConnection;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static ogs.switchon.common.communication.http.ConnectionHandler.disableSslVerification;

public class ClientHandler extends HttpClientHandler {
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
    public ClientHandler(final String domainName, final String contentType, final Integer methodType,
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
    public ClientHandler(final String domainName, final String contentType, final Integer methodType,
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

    private HttpResponse<String> startConnect(final String logToken, final ApplicationData appData) throws IOException, InterruptedException {
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

    private HttpRequest initiateConnection(final HttpRequest httpRequest, final URLConnection urlConnection, final String tokenMessageBytes,
                                                    final String additionalTokenFields) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(connectionTimeOut))
                .build();

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(httpRequest.uri())
                .timeout(Duration.ofMillis(responseTimeOut));

        // Set the request method
        if (methodType != null) {
            requestBuilder.method(methodType.getMethodType(), HttpRequest.BodyPublishers.noBody());
        } else {
            requestBuilder.GET();
        }

        if (this.connectionBean.getContentType() == null) {
            requestBuilder.header(HTTPConstants.CONTENT_TYPE.value(), HTTPConstants.DEFUALT_CHARSET.value());
        } else {
            requestBuilder.header(HTTPConstants.CONTENT_TYPE.value(), this.connectionBean.getContentType() + HTTPConstants.CHARSET.value())
                    .header(HTTPConstants.ACCEPT.value(), this.connectionBean.getContentType());
        }

        setHttpHeader(requestBuilder, tokenMessageBytes, connectionBean.getLogId(), connectionBean.getLogToken(), additionalTokenFields);

        return requestBuilder.build();
    }

    private void setHttpHeader(final HttpRequest.Builder requestBuilder, final String tokenMessageBytes, final String msgId,
                               final String logToken, final String additionalTokenFields) throws IOException {
        String token = null;
        if (this.connectionBean.getDomainName() != null) {
            token = (String) authTokenData.get(this.connectionBean.getDomainName());
            if (token != null)
                tokenGenerateTime = (Long) authTokenData.get(token);
            switch (authType) {
                case 1: // Token authentication
                    if (token == null || (System.currentTimeMillis() - tokenGenerateTime) > tokenExpirePeriod * 60 * 1000) {
                        token = super.generateToken(protocolType, this.connectionBean.getDomainName(),
                                this.connectionBean.getApplicationName(),
                                tokenServicesBean != null ? tokenServicesBean
                                        : this.connectionBean.getTokenServices() != null,
                                this.connectionBean.getUsername(), this.connectionBean.getPassword(),
                                this.connectionBean.getVersionNo(), this.methodType);

                        authTokenData.put(this.connectionBean.getDomainName(), token);
                        this.tokenGenerateTime = System.currentTimeMillis();
                        requestBuilder.header(HTTPConstants.AUTHORIZATION.value(), token);
                    } else
                        requestBuilder.header(HTTPConstants.AUTHORIZATION.value(), token);
                    break;
                case 2:
                    requestBuilder.header((HTTPConstants.USERNAME.value()), this.connectionBean.getUsername())
                                    .header(HTTPConstants.PASSWORD.value(), this.connectionBean.getPassword());

                    break;
                case 3: // Custom headers
                    final Base64.Decoder decoder = Base64.getDecoder();
                    final ObjectMapper objectMapper = new ObjectMapper();
                    final String customHeader = new String(decoder.decode(this.connectionBean.getCustomeHeader()),
                            StandardCharsets.UTF_8);
                    final Map<String, String> map = objectMapper.readValue(customHeader, Map.class);
                    for (final Map.Entry<String, String> header : map.entrySet()) {
                        requestBuilder.header(header.getKey(), header.getValue());
                    }
                    break;
                case 4:
                    if (token == null || (System.currentTimeMillis() - tokenGenerateTime) > tokenExpirePeriod * 60 * 1000) {
                        token = super.generateOauthToken(protocolType, this.connectionBean.getDomainName(),
                                this.connectionBean.getApplicationName() != null
                                        && this.connectionBean.getApplicationName().trim().length() > 0
                                        ? this.connectionBean.getApplicationName() + HTTPConstants.SEPARATOR.value()
                                        : "",
                                tokenServicesBean != null ? tokenServicesBean : this.connectionBean.getTokenServices(),
                                this.connectionBean.getUsername(), this.connectionBean.getPassword(),
                                this.connectionBean.getVersionNo(), this.methodType, tokenMessageBytes, msgId, logToken,
                                connectionBean.getAliasName(), skipCertVerify);

                        authTokenData.put(this.connectionBean.getDomainName(), token);
                        this.tokenGenerateTime = System.currentTimeMillis();
                        authTokenData.put(token, tokenGenerateTime);
                        requestBuilder.header(HTTPConstants.AUTHORIZATION.value(), BEARER_TAG + token);
                    } else
                        requestBuilder.header(HTTPConstants.AUTHORIZATION.value(), BEARER_TAG + token);
                    if (additionalTokenFields != null) {
                        logger.info(msgId + " AdditionalToken fields : " + additionalTokenFields, CLASSNAME, logToken);
                        HashMap<String, String> headersParams;
                        headersParams = (HashMap<String, String>) OBJ_MAPPER.readValue(additionalTokenFields, Map.class);
                        headersParams.entrySet().stream()
                                .forEach(entry -> requestBuilder.header(entry.getKey(), entry.getValue()));
                    }
                    logger.info(msgId + " After token headers setted : ", CLASSNAME, logToken);
                    break;
                case 5: // Original Basic authentication
                    final String credentials = this.connectionBean.getUsername() + ":" + this.connectionBean.getPassword();
                    final String authValue = Base64.getEncoder().encodeToString(credentials.getBytes());
                    requestBuilder.header(HTTPConstants.AUTHORIZATION.value(), "Basic " + authValue);
                    break;
                default: // No authentication
                    break;

            }
        }
    }

    private HttpRequest initiateSecureConnection(final HttpRequest.Builder requestBuilder, final String tokenMessageBytes,
                                                        final String additionalTokenFields) throws IOException {
        // Set the HTTP method (GET, POST, etc.)
        if (methodType != null) {
            requestBuilder.method(methodType.getMethodType(), HttpRequest.BodyPublishers.noBody());
        }

        // Setting timeouts (managed at HttpClient level, not on HttpRequest)
        HttpClient.Builder clientBuilder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(connectionTimeOut));

        // Load SSL certificate if needed
        if (StringUtils.hasText(this.connectionBean.getAliasName())) {
            SSLContext sslContext = SslHelper.loadSSLcertificate(this.connectionBean.getAliasName(), this.skipCertVerify);
            clientBuilder.sslContext(sslContext);
        }

        // Build HttpClient with SSL context and timeouts
        HttpClient client = clientBuilder.build();

        // Set Content-Type and Accept headers
        if (this.connectionBean.getContentType() == null) {
            requestBuilder.header(HTTPConstants.CONTENT_TYPE.value(), HTTPConstants.DEFUALT_CHARSET.value());
        } else {
            requestBuilder.header(HTTPConstants.CONTENT_TYPE.value(), this.connectionBean.getContentType() + HTTPConstants.CHARSET.value())
                    .header(HTTPConstants.ACCEPT.value(), this.connectionBean.getContentType());
        }

        // Add additional headers (e.g., Bearer Token)
        setHttpsHeader(requestBuilder, tokenMessageBytes, connectionBean.getLogId(), connectionBean.getLogToken(), additionalTokenFields);

        // Build the HttpRequest and return it
        return requestBuilder.build();
    }

    private void setHttpsHeader(final HttpRequest.Builder requestBuilder, final String tokenMessageBytes, final String msgId, final String logToken,
                                final String additionalTokenFields) throws IOException {
        String token = null;
        if (this.connectionBean.getDomainName() != null) {
            token = (String) authTokenData.get(this.connectionBean.getDomainName());
            if (token != null)
                tokenGenerateTime = (Long) authTokenData.get(token);
            switch (authType) {
                case 1: // Token authentication
                    if (token == null || (System.currentTimeMillis() - tokenGenerateTime) > tokenExpirePeriod * 60 * 1000) {
                        token = super.generateToken(protocolType, this.connectionBean.getDomainName(),
                                this.connectionBean.getApplicationName(),
                                tokenServicesBean != null ? tokenServicesBean
                                        : this.connectionBean.getTokenServices() != null,
                                this.connectionBean.getUsername(), this.connectionBean.getPassword(),
                                this.connectionBean.getVersionNo(), this.methodType);

                        authTokenData.put(this.connectionBean.getDomainName(), token);
                        this.tokenGenerateTime = System.currentTimeMillis();
                        requestBuilder.header(HTTPConstants.AUTHORIZATION.value(), token);
                    } else
                        requestBuilder.header(HTTPConstants.AUTHORIZATION.value(), token);
                    break;
                case 2: // Basic authentication
                    requestBuilder.header(HTTPConstants.USERNAME.value(), this.connectionBean.getUsername());
                    requestBuilder.header(HTTPConstants.PASSWORD.value(), this.connectionBean.getPassword());
                    break;
                case 3: // Custom headers
                    final Base64.Decoder decoder = Base64.getDecoder();
                    final ObjectMapper objectMapper = new ObjectMapper();
                    final String customHeader = new String(decoder.decode(this.connectionBean.getCustomeHeader()),
                            StandardCharsets.UTF_8);
                    final Map<String, String> map = objectMapper.readValue(customHeader, Map.class);
                    for (final Map.Entry<String, String> header : map.entrySet()) {
                        requestBuilder.header(header.getKey(), header.getValue());
                    }
                    break;
                case 4:
                    if (token == null || (System.currentTimeMillis() - tokenGenerateTime) > tokenExpirePeriod * 60 * 1000) {
                        token = super.generateOauthToken(protocolType, this.connectionBean.getDomainName(),
                                this.connectionBean.getApplicationName() != null
                                        && this.connectionBean.getApplicationName().trim().length() > 0
                                        ? this.connectionBean.getApplicationName() + HTTPConstants.SEPARATOR.value()
                                        : "",
                                tokenServicesBean != null ? tokenServicesBean : this.connectionBean.getTokenServices(),
                                this.connectionBean.getUsername(), this.connectionBean.getPassword(),
                                this.connectionBean.getVersionNo(), this.methodType, tokenMessageBytes, msgId, logToken,
                                connectionBean.getAliasName(), skipCertVerify);

                        authTokenData.put(this.connectionBean.getDomainName(), token);
                        this.tokenGenerateTime = System.currentTimeMillis();
                        authTokenData.put(token, tokenGenerateTime);
                        requestBuilder.header(HTTPConstants.AUTHORIZATION.value(), BEARER_TAG + token);
                    } else
                        requestBuilder.header(HTTPConstants.AUTHORIZATION.value(), BEARER_TAG + token);
                    if (additionalTokenFields != null) {
                        logger.info(msgId + " AdditionalToken fields : " + additionalTokenFields, CLASSNAME, logToken);
                        HashMap<String, String> headersParams;
                        headersParams = (HashMap<String, String>) OBJ_MAPPER.readValue(additionalTokenFields, Map.class);
                        headersParams.entrySet().stream()
                                .forEach(entry -> requestBuilder.header(entry.getKey(), entry.getValue()));
                    }
                    logger.info(msgId + " After token headers setted : ", CLASSNAME, logToken);
                    break;
                case 5: // Original Basic authentication
                    final String credentials = this.connectionBean.getUsername() + ":" + this.connectionBean.getPassword();
                    final String authValue = Base64.getEncoder().encodeToString(credentials.getBytes());
                    requestBuilder.header(HTTPConstants.AUTHORIZATION.value(), "Basic " + authValue);
                    break;
                default: // No authentication
                    break;
            }
        }
    }
}
