package com.icegreen.greenmail.pop3.commands;

import com.icegreen.greenmail.junit.GreenMailRule;
import com.icegreen.greenmail.user.GreenMailUser;
import com.icegreen.greenmail.user.TokenValidator;
import com.icegreen.greenmail.user.UserException;
import com.icegreen.greenmail.util.ServerSetup;
import com.icegreen.greenmail.util.ServerSetupTest;
import org.junit.Rule;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

public class Pop3AuthXOAuth2LoginTest {

    @Rule
    public final GreenMailRule greenMail = new GreenMailRule(ServerSetupTest.POP3);

    private Socket pop3Socket;
    private PrintWriter pop3Writer;
    private BufferedReader pop3Reader;

    private void connect() throws IOException {
        final ServerSetup pop3Setup = greenMail.getPop3().getServerSetup();
        pop3Socket = new Socket(pop3Setup.getBindAddress(), pop3Setup.getPort());
        pop3Writer = new PrintWriter(new OutputStreamWriter(pop3Socket.getOutputStream(), StandardCharsets.UTF_8), true);
        pop3Reader = new BufferedReader(new InputStreamReader(pop3Socket.getInputStream(), StandardCharsets.UTF_8));
        assertThat(pop3Reader.readLine()).startsWith("+OK"); // Welcome message
    }

    private void disconnect() throws IOException {
        if (pop3Reader != null) {
            pop3Reader.close();
        }
        if (pop3Writer != null) {
            pop3Writer.close();
        }
        if (pop3Socket != null) {
            pop3Socket.close();
        }
    }

    private String executeCommand(String command) throws IOException {
        pop3Writer.println(command);
        return pop3Reader.readLine();
    }

    @Test
    public void testSuccessfulXOAuth2Login() throws IOException, UserException {
        final String email = "testuser@localhost";
        final String token = "someAccessToken";

        GreenMailUser user = greenMail.getUserManager().createUser(email, "loginId", "password");
        user.setTokenValidator(receivedToken -> token.equals(receivedToken));

        connect();
        try {
            String xoauth2String = "user=" + email + "\1auth=Bearer " + token + "\1\1";
            String base64Xoauth2String = Base64.getEncoder().encodeToString(xoauth2String.getBytes(StandardCharsets.UTF_8));

            String response = executeCommand("AUTH XOAUTH2 " + base64Xoauth2String);
            assertThat(response).startsWith("+OK");

        } finally {
            executeCommand("QUIT");
            disconnect();
        }
    }

    @Test
    public void testFailedXOAuth2LoginInvalidToken() throws IOException, UserException {
        final String email = "testuser2@localhost";
        final String correctToken = "correctAccessToken";
        final String wrongToken = "wrongAccessToken";

        GreenMailUser user = greenMail.getUserManager().createUser(email, "loginId2", "password2");
        user.setTokenValidator(receivedToken -> correctToken.equals(receivedToken));

        connect();
        try {
            String xoauth2String = "user=" + email + "\1auth=Bearer " + wrongToken + "\1\1";
            String base64Xoauth2String = Base64.getEncoder().encodeToString(xoauth2String.getBytes(StandardCharsets.UTF_8));

            String response = executeCommand("AUTH XOAUTH2 " + base64Xoauth2String);
            assertThat(response).startsWith("-ERR");

        } finally {
            // Try QUIT even if auth fails, to clean up server state if connection is still open
            try {
                 executeCommand("QUIT");
            } catch (IOException e) {
                // Ignore, socket might be closed by server after failed auth
            }
            disconnect();
        }
    }

    @Test
    public void testFailedXOAuth2LoginMalformedResponseNotBase64() throws IOException, UserException {
        greenMail.getUserManager().createUser("testuser3@localhost", "loginId3", "password3");
        // No TokenValidator needed as the command should fail before validator is invoked.

        connect();
        try {
            String response = executeCommand("AUTH XOAUTH2 ThisIsNotBase64");
            assertThat(response).startsWith("-ERR");
            assertThat(response).contains("base64"); // Expecting error message about base64 encoding

        } finally {
            try {
                 executeCommand("QUIT");
            } catch (IOException e) {
                // Ignore
            }
            disconnect();
        }
    }

    @Test
    public void testFailedXOAuth2LoginMalformedResponseBadFormat() throws IOException, UserException {
        final String email = "testuser4@localhost";
        final String token = "someToken";
        GreenMailUser user = greenMail.getUserManager().createUser(email, "loginId4", "password4");
        // Token validator setup, though it might not be reached if parsing fails early
        user.setTokenValidator(receivedToken -> token.equals(receivedToken));


        connect();
        try {
            // Malformed: missing the Bearer part or structure
            String malformedXoauth2String = "user=" + email + "\1auth=" + token + "\1\1";
            String base64MalformedXoauth2String = Base64.getEncoder().encodeToString(malformedXoauth2String.getBytes(StandardCharsets.UTF_8));

            String response = executeCommand("AUTH XOAUTH2 " + base64MalformedXoauth2String);
            assertThat(response).startsWith("-ERR");
            assertThat(response).contains("invalid XOAUTH2 token format");


            // Malformed: empty user
            String malformedXoauth2String2 = "user=\1auth=Bearer " + token + "\1\1";
            String base64MalformedXoauth2String2 = Base64.getEncoder().encodeToString(malformedXoauth2String2.getBytes(StandardCharsets.UTF_8));
            response = executeCommand("AUTH XOAUTH2 " + base64MalformedXoauth2String2);
            assertThat(response).startsWith("-ERR");
            assertThat(response).contains("invalid XOAUTH2 token format");


            // Malformed: empty token
            String malformedXoauth2String3 = "user=" + email + "\1auth=Bearer \1\1";
            String base64MalformedXoauth2String3 = Base64.getEncoder().encodeToString(malformedXoauth2String3.getBytes(StandardCharsets.UTF_8));
            response = executeCommand("AUTH XOAUTH2 " + base64MalformedXoauth2String3);
            assertThat(response).startsWith("-ERR");
            assertThat(response).contains("invalid XOAUTH2 token format");

        } finally {
            try {
                 executeCommand("QUIT");
            } catch (IOException e) {
                // Ignore
            }
            disconnect();
        }
    }
    
    @Test
    public void testFailedXOAuth2LoginUserWithoutTokenValidator() throws IOException, UserException {
        final String email = "testuser5@localhost";
        final String token = "anyToken";
        // User created BUT NO TokenValidator set
        greenMail.getUserManager().createUser(email, "loginId5", "password5");

        connect();
        try {
            String xoauth2String = "user=" + email + "\1auth=Bearer " + token + "\1\1";
            String base64Xoauth2String = Base64.getEncoder().encodeToString(xoauth2String.getBytes(StandardCharsets.UTF_8));

            String response = executeCommand("AUTH XOAUTH2 " + base64Xoauth2String);
            // This should fail because UserManager.test() will use the regular password "password5"
            // against the provided token, which won't match.
            // Or, if TokenValidator is explicitly checked for null by UserManager for XOAUTH2 flow, it would also fail.
            assertThat(response).startsWith("-ERR");
            // The exact error message might vary, but it should indicate failed authentication
            assertThat(response).contains("invalid credentials or token");


        } finally {
            try {
                 executeCommand("QUIT");
            } catch (IOException e) {
                // Ignore
            }
            disconnect();
        }
    }

    @Test
    public void testSuccessfulXOAuth2LoginWithServerPrompt() throws IOException, UserException {
        final String email = "testuser6@localhost";
        final String token = "promptedAccessToken";

        GreenMailUser user = greenMail.getUserManager().createUser(email, "loginId6", "password6");
        user.setTokenValidator(receivedToken -> token.equals(receivedToken));

        connect();
        try {
            // Send AUTH XOAUTH2 without initial response
            pop3Writer.println("AUTH XOAUTH2");
            String serverPrompt = pop3Reader.readLine();
            assertThat(serverPrompt).startsWith("+ "); // Expecting continuation

            String xoauth2String = "user=" + email + "\1auth=Bearer " + token + "\1\1";
            String base64Xoauth2String = Base64.getEncoder().encodeToString(xoauth2String.getBytes(StandardCharsets.UTF_8));
            
            String response = executeCommand(base64Xoauth2String); // Send the token after prompt
            assertThat(response).startsWith("+OK");

        } finally {
            executeCommand("QUIT");
            disconnect();
        }
    }
}
