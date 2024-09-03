//package ogs.switchon.common.communication.http;
//
//import ogs.switchon.common.communication.http.constants.ProtocolType;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//
//import java.io.IOException;
//import java.net.URI;
//import java.net.http.HttpClient;
//import java.net.http.HttpRequest;
//import java.net.http.HttpResponse;
//
//import static javax.management.Query.times;
//import static jdk.internal.org.objectweb.asm.util.CheckClassAdapter.verify;
//import static jdk.jfr.internal.jfc.model.Constraint.any;
//import static org.junit.jupiter.api.Assertions.*;
//
//public class HttpConnectionHandlerTest {
//    import org.junit.jupiter.api.Test;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.extension.ExtendWith;
//import org.mockito.InjectMocks;
//import org.mockito.Mock;
//import org.mockito.Mockito;
//import org.mockito.junit.jupiter.MockitoExtension;
//
//import java.io.IOException;
//import java.net.URI;
//import java.net.http.HttpClient;
//import java.net.http.HttpRequest;
//import java.net.http.HttpResponse;
//import java.net.http.HttpResponse.BodyHandlers;
//
//import static org.junit.jupiter.api.Assertions.*;
//import static org.mockito.ArgumentMatchers.any;
//import static org.mockito.Mockito.*;
//
//    @ExtendWith(MockitoExtension.class)
//    class MyServiceTest {
//
//        @InjectMocks
//        private ConnectionHandler myService;  // Replace with your actual service class
//
//        @Mock
//        private HttpClient mockHttpClient;
//
//        @Mock
//        private HttpResponse<String> mockHttpResponse;
//
//        private final String domainName = "example.com";
//        private final String servicePath = "api/v1/resource";
//        private final ProtocolType protocolType = ProtocolType.HTTP;
//
//        @BeforeEach
//        void setUp() {
//            // Set up the mocks if needed
//        }
//
//        @Test
//        void testOpenConnectionSuccess() throws IOException, InterruptedException {
//            // Arrange
//            final String expectedUrl = protocolType.getProtocol() + domainName + "/" + servicePath;
//            //when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(mockHttpResponse);
//            //when(mockHttpResponse.body()).thenReturn("Expected response");
//
//            // Act
//            //HttpResponse<String> response = myService.openConnection(domainName, protocolType, servicePath);
//
//            // Assert
//            //assertNotNull(response);
//            //assertEquals("Expected response", response.body());
//            //verify(mockHttpClient, times(1)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
//            //verify(mockHttpResponse, times(1)).body();
//
//        }
//
//
//    }
//
//}
