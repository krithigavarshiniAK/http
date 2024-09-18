package ogs.switchon.common.communication.http.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import ogs.switchon.common.communication.http.ConnectionBean;
import ogs.switchon.common.communication.http.TokenBean;
import ogs.switchon.common.communication.http.constants.HTTPConstants;
import ogs.switchon.common.communication.http.constants.MethodType;
import ogs.switchon.common.communication.http.constants.ProtocolType;

import java.io.IOException;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class HttpRequestHeaderHelper {

    private static ConnectionBean connectionBean;
    private static TokenBean tokenServicesBean;
    private static int authType;
    private static MethodType methodType;
    private static Map<String, Object> authTokenData;
    private static long tokenGenerateTime;
    private static long tokenExpirePeriod;
    private static boolean skipCertVerify;
    private static String protocolType;

    private static final String BEARER_TAG = "Bearer ";
    private static final ObjectMapper OBJ_MAPPER = new ObjectMapper();
    private static HttpClientHandler httpClientHandler;

    public HttpRequestHeaderHelper(HttpClientHandler httpClientHandler, ConnectionBean connectionBean,
                                   TokenBean tokenServicesBean, int authType, String protocolType,
                                   MethodType methodType, Map<String, Object> authTokenData, long tokenExpirePeriod,
                                   boolean skipCertVerify) {
        this.httpClientHandler = httpClientHandler;
        this.connectionBean = connectionBean;
        this.tokenServicesBean = tokenServicesBean;
        this.authType = authType;
        this.protocolType = protocolType;
        this.methodType = methodType;
        this.authTokenData = authTokenData;
        this.tokenExpirePeriod = tokenExpirePeriod;
        this.skipCertVerify = skipCertVerify;
    }

    public static HttpRequest.Builder setHttpHeader(final HttpRequest.Builder requestBuilder, final String tokenMessageBytes,
                                             final String msgId, final String logToken, final String additionalTokenFields)
            throws IOException {

        String token;

        if (connectionBean.getDomainName() != null) {
            token = (String) authTokenData.get(connectionBean.getDomainName());
            if (token != null) {
                tokenGenerateTime = (Long) authTokenData.get(token);
            }

            switch (authType) {
                case 1:
                    if (token == null || (System.currentTimeMillis() - tokenGenerateTime) > tokenExpirePeriod * 60 * 1000) {
                        token = httpClientHandler.generateToken(
                                ProtocolType.valueOf(protocolType),
                                connectionBean.getDomainName(),
                                connectionBean.getApplicationName(),
                                tokenServicesBean != null ? tokenServicesBean : connectionBean.getTokenServices(),
                                connectionBean.getUsername(),
                                connectionBean.getPassword(),
                                connectionBean.getVersionNo(),
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
                        token = httpClientHandler.generateOauthToken(
                                ProtocolType.valueOf(protocolType),
                                connectionBean.getDomainName(),
                                connectionBean.getApplicationName(),
                                tokenServicesBean != null ? tokenServicesBean : connectionBean.getTokenServices(),
                                connectionBean.getUsername(),
                                connectionBean.getPassword(),
                                connectionBean.getVersionNo(),
                                methodType,
                                tokenMessageBytes,
                                msgId,
                                logToken,
                                connectionBean.getAliasName(),
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

        requestBuilder.header("Content-Type", "application/json")
                .header("UserId", "user@paytabs");

        return requestBuilder;
    }
}

