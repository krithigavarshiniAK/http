package ogs.switchon.common.communication.http;

import com.fasterxml.jackson.databind.ObjectMapper;
import ogs.switchon.common.communication.http.constants.MethodType;
import ogs.switchon.common.communication.http.constants.ProtocolType;
import ogs.switchon.common.communication.http.exception.TokenGenerationFailure;
import ogs.switchon.common.communication.http.utils.HttpClientHandler;
import ogs.switchon.common.communication.http.utils.HttpRequestHeaderHelper;
import ogs.switchon.common.exceptions.SocketClosedException;
import org.junit.jupiter.api.Test;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;

import static ogs.switchon.common.communication.http.utils.HttpRequestHeaderHelper.setHttpHeader;
import static org.junit.Assert.assertNotEquals;
import static org.junit.jupiter.api.Assertions.*;

public class HttpConnectionHandlerTest{

    private String logId = "logId123";

    private String logToken = "logToken456";

    private final String domainName = "jsonplaceholder.typicode.com";

    private final String servicePath = "api/v1/resource";

    private final ProtocolType protocolType = ProtocolType.HTTPS;

    private final String applicationName = "myApp";

    private final String username = "user";

    private final String password = "password";

    private final String VersionNo = "v1";

    private final boolean skipCertVerify = true;

    @Test
    void testOpenConnection_Positive() throws IOException, InterruptedException {
        HttpClientHandler httpClientHandler = new HttpClientHandler();

        HttpRequest request = httpClientHandler.OpenConnection(domainName, protocolType, servicePath);

        assertNotNull(request, "HttpRequest should not be null");
        assertEquals("https://jsonplaceholder.typicode.com/api/v1/resource", request.uri().toString(), "The URI should match the input");
    }

    @Test
    void testOpenConnection_Negative() throws IOException, InterruptedException {
        HttpClientHandler httpClientHandler = new HttpClientHandler();

        HttpRequest request = httpClientHandler.OpenConnection(domainName, ProtocolType.HTTP, "/api");

        assertNotNull(request, "HttpRequest should not be null");
        assertNotEquals("https://jsonplaceholder.typicode.com/api/v1/resource", request.uri().toString(), "The URI should not match the valid URL");
    }

    @Test
    void testOpenConnection_Missing() throws IOException,InterruptedException{
        HttpClientHandler httpClientHandler = new HttpClientHandler();

        Exception exception = assertThrows(NullPointerException.class, () -> {
            httpClientHandler.OpenConnection(null, ProtocolType.HTTP,null);
        });
    }

    @Test
    void testWriteAndRead_Positive() throws IOException, InterruptedException{
        ObjectMapper objectMapper = new ObjectMapper();
        byte[] response = null;
        HttpClientHandler httpClientHandler = new HttpClientHandler();

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        BufferedOutputStream outputStream = new BufferedOutputStream(byteArrayOutputStream);

        response = httpClientHandler.writeAndRead(outputStream,  new byte[0], logId, logToken, objectMapper);

        assertNotNull(response, "Write and Read is not null");
    }

    @Test
    void testWriteAndRead_Negative() throws IOException, InterruptedException{
        ObjectMapper objectMapper = new ObjectMapper();
        byte[] response = null;
        HttpClientHandler httpClientHandler = new HttpClientHandler();

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        BufferedOutputStream outputStream = new BufferedOutputStream(byteArrayOutputStream);

        response = httpClientHandler.writeAndRead(outputStream,  new byte[0], logId, logToken, objectMapper);

        assertNotNull(response, "Write and Read is not null");
    }

    @Test
    void testWriteAndRead_Missing() throws IOException, InterruptedException{
        ObjectMapper objectMapper = new ObjectMapper();
        HttpClientHandler httpClientHandler = new HttpClientHandler();

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        BufferedOutputStream outputStream = new BufferedOutputStream(byteArrayOutputStream);


        Exception exception = assertThrows(NullPointerException.class, () -> {
            httpClientHandler.writeAndRead(outputStream,  new byte[0], logId, logToken, objectMapper);
        });
    }

    @Test
    void testSetHttpHeaders() throws IOException {
        HttpRequest.Builder builder = HttpRequest.newBuilder();

        setHttpHeader(builder, null, logId, logToken, null);
    }

    @Test
    void testTokenGenerate_Positive() throws TokenGenerationFailure{
        HttpClientHandler httpClientHandler = new HttpClientHandler();

        String response = httpClientHandler.generateToken(protocolType, domainName, null, applicationName, username, password, VersionNo, null);

        assertNotNull(response, "Generate token is working should not be null.");
    }

    @Test
    void testTokenGenerate_Missing() throws TokenGenerationFailure {

        HttpClientHandler httpClientHandler = new HttpClientHandler();

        Exception exception = assertThrows(NullPointerException.class, () -> {
            httpClientHandler.generateToken(
                    null, domainName, null, applicationName, null, password, VersionNo, null);
        });
    }

    @Test
    void testGenerateOAuthToken_Missing() throws TokenGenerationFailure{

        HttpClientHandler httpClientHandler = new HttpClientHandler();

        Exception exception = assertThrows(NullPointerException.class, () -> {
            httpClientHandler.generateOauthToken(
                    null, null, null, applicationName, username, password,
                    VersionNo, null, null, null, logToken, null, skipCertVerify);
        });
    }

    @Test
    void testGenerateOAuthToken_Negative() throws TokenGenerationFailure{

        HttpClientHandler httpClientHandler = new HttpClientHandler();

        Exception exception = assertThrows(RuntimeException.class, () -> {
            httpClientHandler.generateOauthToken(
                    protocolType, domainName, null, applicationName, username, password,
                    VersionNo, null, null, null, logToken, null, skipCertVerify);
        });
    }
}
