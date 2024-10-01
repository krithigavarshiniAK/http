package ogs.switchon.common.communication.http;

import com.fasterxml.jackson.databind.ObjectMapper;
import ogs.switchon.common.communication.http.constants.MethodType;
import ogs.switchon.common.communication.http.constants.ProtocolType;
import ogs.switchon.common.communication.http.exception.TokenGenerationFailure;
import ogs.switchon.common.communication.http.utils.HttpConnectionHandler;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;


public class HttpClientConnectionHandlerTest {

    private String logId = "logId123";

    private String logToken = "logToken456";

    private static String contentType = "application/json";

    private final String domainName = "jsonplaceholder.typicode.com";

    private final String servicePath = "api/v1/resource";

    private final ProtocolType protocolType = ProtocolType.HTTPS;

    private final String applicationName = "myApp";

    private final String username = "user";

    private final String password = "password";

    private final String VersionNo = "v1";

    private final boolean skipCertVerify = true;

    private String url = "https://jsonplaceholder.typicode.com/api/v1/resource";

    @Test
    void testOpenConnection_Positive() throws IOException, InterruptedException {
        HttpConnectionHandler httpConnectionHandler = new HttpConnectionHandler();

        HttpRequest.Builder request = httpConnectionHandler.OpenConnection(domainName, protocolType, servicePath);

        assertNotNull(request, "HttpRequest should not be null");
    }

    @Test
    void testOpenConnection_Missing() throws IOException,InterruptedException{
        HttpConnectionHandler httpConnectionHandler = new HttpConnectionHandler();

        Exception exception = assertThrows(NullPointerException.class, () -> {
            httpConnectionHandler.OpenConnection(null, ProtocolType.HTTP,null);
        });
    }

    @Test
    void testWriteAndRead() throws IOException, InterruptedException {
        HttpClient httpClient = HttpClient.newHttpClient();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://httpbin.org/post"))
                .POST(HttpRequest.BodyPublishers.ofString("Test data"))
                .build();

        byte[] msgDataBytes = "Test message".getBytes(StandardCharsets.UTF_8);

        ObjectMapper objectMapper = new ObjectMapper();

        HttpConnectionHandler httpClientConnection = new HttpConnectionHandler();
        byte[] responseBytes = httpClientConnection.writeAndRead(httpClient, request, msgDataBytes, logId, logToken, objectMapper);

        assertNotNull(responseBytes);
        assertTrue(responseBytes.length > 0);
    }

    @Test
    void testSetHttpHeaders() throws IOException {
        HttpRequest.Builder builder = HttpRequest.newBuilder();
        ConnectionHandler clientHandler = new ConnectionHandler(domainName, contentType, 1, false, null, null, null, applicationName,
                VersionNo, servicePath, 30, 30, null,null, null, logToken, "", null, 0, 10l, 30, null, null, null, false );
        clientHandler.setHttpHeader(builder, null, logId, logToken, null);
    }

    @Test
    void testTokenGenerate_Positive() throws TokenGenerationFailure{
        HttpConnectionHandler httpConnectionHandler = new HttpConnectionHandler();

        String response = httpConnectionHandler.generateToken(protocolType, domainName, null, applicationName, username, password, VersionNo, null);

        assertNotNull(response, "Generate token is working should not be null.");
    }

    @Test
    void testTokenGenerate_Missing() throws TokenGenerationFailure {

        HttpConnectionHandler httpConnectionHandler = new HttpConnectionHandler();

        Exception exception = assertThrows(NullPointerException.class, () -> {
            httpConnectionHandler.generateToken(
                    null, domainName, null, applicationName, null, password, VersionNo, null);
        });
    }

    @Test
    void testGenerateOAuthToken_Missing() throws TokenGenerationFailure{

        HttpConnectionHandler httpConnectionHandler = new HttpConnectionHandler();

        Exception exception = assertThrows(NullPointerException.class, () -> {
            httpConnectionHandler.generateOauthToken(
                    null, "", null, applicationName, username, password,
                    VersionNo, null, null, null, logToken, null, skipCertVerify);
        });
    }

    @Test
    void testGenerateOAuthToken_Positive() throws TokenGenerationFailure{
        HttpConnectionHandler httpConnectionHandler = new HttpConnectionHandler();

        String response = httpConnectionHandler.generateOauthToken(protocolType, domainName, null, applicationName, username, password,
                VersionNo, null, null, null, logToken, null, skipCertVerify);

        assertNotNull(response, "Generate token is working should not be null.");
    }

    @Test
    void testPushRequest_HttpUrl() throws Exception {
        byte[] messageBytes = "Test HTTP Message".getBytes();
        String fullUrl = "http://example.com/api";
        MethodType method = MethodType.POST;

        ConnectionHandler clientHandler = new ConnectionHandler(domainName, contentType, 1, false, null, null, null, applicationName,
                VersionNo, servicePath, 30, 30, null,null, null, logToken, "", null, 0, 10l, 30, null, null, null, false );
        byte[] responseBytes = clientHandler.pushRequest(messageBytes, fullUrl, method, null);

        assertNotNull(responseBytes);
        assertTrue(responseBytes.length > 0);
    }

    @Test
    void testPushSecuredRequest_HttpsUrl() throws Exception {
        byte[] messageBytes = "Test HTTPS Message".getBytes();
        String fullUrl = "https://example.com/api";
        MethodType method = MethodType.POST;

        ConnectionHandler clientHandler = new ConnectionHandler(domainName, contentType, 1, false, null, null, null, applicationName,
                VersionNo, servicePath, 30, 30, null,null, null, logToken, "", null, 0, 10l, 30, null, null, null, false );
        byte[] responseBytes = clientHandler.pushSecuredRequest(messageBytes, fullUrl, method, null, "myKeyAlias", true);

        assertNotNull(responseBytes);
        assertTrue(responseBytes.length > 0);
    }

    @Test
    public void testDoRequest()throws Exception{
        ConnectionHandler clientHandler = new ConnectionHandler(domainName, contentType, 1, false, null, null, null, applicationName,
                VersionNo, servicePath, 30, 30, null,null, null, logToken, "", null, 0, 10l, 30, null, null, null, false );
        byte[] response = clientHandler.doRequest(logToken,new byte[0], logId,null, null);
        assertNotNull(response, "Response cannot be null.");
    }
}