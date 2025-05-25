/*
 * Copyright (c) 2014 Wael Chatila / Icegreen Technologies. All Rights Reserved.
 * This software is released under the Apache license 2.0
 * This file has been used and modified.
 * Original file can be found on http://foedus.sourceforge.net
 */
package com.icegreen.greenmail.pop3.commands;

import com.icegreen.greenmail.pop3.Pop3Connection;
import com.icegreen.greenmail.pop3.Pop3State;
import com.icegreen.greenmail.store.FolderException;
import com.icegreen.greenmail.user.GreenMailUser;
import com.icegreen.greenmail.user.UserException;
import com.icegreen.greenmail.util.EncodingUtil;
import com.icegreen.greenmail.util.SaslMessage;

import java.io.IOException;
import java.util.Arrays;

/**
 * SASL : PLAIN
 * <p>
 * <a href="https://tools.ietf.org/html/rfc5034">...</a>
 * <p>
 * AUTH mechanism [initial-response]
 * mechanism PLAIN : See <a href="https://tools.ietf.org/html/rfc4616">...</a>
 */
package com.icegreen.greenmail.pop3.commands;

import com.icegreen.greenmail.pop3.Pop3Connection;
import com.icegreen.greenmail.pop3.Pop3State;
import com.icegreen.greenmail.smtp.auth.XOAuth2AuthenticationState; // Import for XOAUTH2
import com.icegreen.greenmail.store.FolderException;
import com.icegreen.greenmail.user.GreenMailUser;
import com.icegreen.greenmail.user.UserException;
import com.icegreen.greenmail.util.EncodingUtil;
import com.icegreen.greenmail.util.SaslMessage;

import java.io.IOException;
import java.util.Arrays;

/**
 * SASL : PLAIN, XOAUTH2
 * <p>
 * <a href="https://tools.ietf.org/html/rfc5034">...</a>
 * <p>
 * AUTH mechanism [initial-response]
 * mechanism PLAIN : See <a href="https://tools.ietf.org/html/rfc4616">...</a>
 * mechanism XOAUTH2 : See <a href="https://developers.google.com/gmail/xoauth2_protocol">...</a>
 */
public class AuthCommand
        extends Pop3Command {

    public static final String CONTINUATION = "+ ";

    @Override
    public boolean isValidForState(Pop3State state) {

        return !state.isAuthenticated();
    }

    public enum Pop3SaslAuthMechanism {
        PLAIN, XOAUTH2; // Added XOAUTH2

        /**
         * WS separated list of supported auth mechanism.
         *
         * @return a list of supported auth mechanism.
         */
        static String list() {
            StringBuilder buf = new StringBuilder();
            for (Pop3SaslAuthMechanism mechanism : values()) {
                if (buf.length() > 0) {
                    buf.append(' ');
                }
                buf.append(mechanism.name());
            }
            return buf.toString();
        }
    }

    @Override
    public void execute(Pop3Connection conn, Pop3State state, String cmd) {
        if (state.isAuthenticated()) {
            conn.println("-ERR Already authenticated");
            return;
        }

        String[] args = cmd.split(" ");
        if (args.length < 2) {
            conn.println("-ERR Required syntax: AUTH mechanism [initial-response]");
            return;
        }

        String mechanism = args[1];
        if (Pop3SaslAuthMechanism.PLAIN.name().equalsIgnoreCase(mechanism)) {
            authPlain(conn, state, args);
        } else if (Pop3SaslAuthMechanism.XOAUTH2.name().equalsIgnoreCase(mechanism)) {
            authXoauth2(conn, state, args); // Call new method for XOAUTH2
        } else {
            conn.println("-ERR Required syntax: AUTH mechanism <" + mechanism +
                    "> not supported, expected one of " + Arrays.toString(Pop3SaslAuthMechanism.values()));
        }
    }

    private void authPlain(Pop3Connection conn, Pop3State state, String[] args) {
        // https://tools.ietf.org/html/rfc4616
        String initialResponse;
        if (args.length == 2 || args.length == 3 && "=".equals(args[2])) { // Continuation?
            conn.println(CONTINUATION);
            try {
                initialResponse = conn.readLine();
            } catch (IOException e) {
                conn.println("-ERR Invalid syntax, expected continuation with iniital-response");
                return;
            }
        } else if (args.length == 3) {
            initialResponse = args[2];
        } else {
            conn.println("-ERR Invalid syntax, expected initial-response : AUTH PLAIN [initial-response]");
            return;
        }

        // authorization-id\0authentication-id\0passwd
        final SaslMessage saslMessage;
        try {
            saslMessage = SaslMessage.parse(EncodingUtil.decodeBase64(initialResponse));
        } catch(IllegalArgumentException ex) { // Invalid Base64
            log.error("Expected base64 encoding but got <{}>", initialResponse, ex); /* GreenMail is just a test server */
            conn.println("-ERR Authentication failed, expected base64 encoding : " + ex.getMessage() );
            return;
        }

        GreenMailUser user;
        try {
            user = state.getUser(saslMessage.getAuthcid());
            state.setUser(user);
        } catch (UserException e) {
            log.error("Can not get user <{}>", saslMessage.getAuthcid(), e);
            conn.println("-ERR Authentication failed: " + e.getMessage() /* GreenMail is just a test server */);
            return;
        }

        try {
            state.authenticate(saslMessage.getPasswd());
            conn.println("+OK");
        } catch (UserException e) {
            log.error("Can not authenticate using user <{}>", user.getLogin(), e);
            conn.println("-ERR Authentication failed: " + e.getMessage());
        } catch (FolderException e) {
            log.error("Can not authenticate using user {}, internal error", user, e);
            conn.println("-ERR Authentication failed, internal error: " + e.getMessage());
        }
    }

    private void authXoauth2(Pop3Connection conn, Pop3State state, String[] args) {
        String initialResponse;
        if (args.length == 2 || args.length == 3 && "=".equals(args[2])) { // Continuation?
            conn.println(CONTINUATION);
            try {
                initialResponse = conn.readLine();
                if (null == initialResponse || initialResponse.isEmpty()) {
                    conn.println("-ERR Authentication failed, empty response");
                    return;
                }
            } catch (IOException e) {
                conn.println("-ERR Invalid syntax, expected continuation with initial-response");
                return;
            }
        } else if (args.length == 3) {
            initialResponse = args[2];
        } else {
            conn.println("-ERR Invalid syntax, expected initial-response : AUTH XOAUTH2 [initial-response]");
            return;
        }

        final String decodedInitialResponse;
        try {
            decodedInitialResponse = EncodingUtil.decodeBase64(initialResponse);
        } catch (IllegalArgumentException ex) { // Invalid Base64
            log.error("Expected base64 encoding for XOAUTH2 but got <{}>", initialResponse, ex);
            conn.println("-ERR Authentication failed, expected base64 encoding : " + ex.getMessage());
            return;
        }

        final XOAuth2AuthenticationState.XOAuth2Credentials credentials;
        try {
            credentials = XOAuth2AuthenticationState.parse(decodedInitialResponse);
            if (credentials == null || credentials.getUser() == null || credentials.getOauth2Token() == null) {
                conn.println("-ERR Authentication failed, invalid XOAUTH2 token format");
                return;
            }
        } catch (IllegalArgumentException ex) {
            log.error("Failed to parse XOAUTH2 token <{}>", decodedInitialResponse, ex);
            conn.println("-ERR Authentication failed, could not parse XOAUTH2 token: " + ex.getMessage());
            return;
        }

        GreenMailUser user;
        try {
            // For XOAUTH2, the 'user' part of the token is the username
            user = state.getUser(credentials.getUser());
            state.setUser(user); // Set user in state for context, actual auth happens next
        } catch (UserException e) {
            log.error("Can not get user <{}> from XOAUTH2 token", credentials.getUser(), e);
            conn.println("-ERR Authentication failed: " + e.getMessage());
            return;
        }

        try {
            // Authenticate using the username and the OAuth token
            // We might need a new method in Pop3State or UserManager if test() is not suitable
            if (state.getManager().test(user.getLogin(), credentials.getOauth2Token())) {
                state.setAuthenticated(true); // Mark state as authenticated
                conn.println("+OK");
            } else {
                conn.println("-ERR Authentication failed, invalid credentials or token");
            }
        } catch (UserException e) { // Should not happen if test() is used, but good practice
            log.error("Can not authenticate XOAUTH2 user <{}>", user.getLogin(), e);
            conn.println("-ERR Authentication failed: " + e.getMessage());
        }
    }
}
