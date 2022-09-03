/*
 * Copyright (C) 2018-2021 Confidential Technologies GmbH
 *
 * You can purchase a commercial license at https://hwsecurity.dev.
 * Buying such a license is mandatory as soon as you develop commercial
 * activities involving this program without disclosing the source code
 * of your own applications.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.cotech.hw.fido2.internal.pinauth;


import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import de.cotech.hw.fido2.exceptions.FidoClientPinBlockedException;
import de.cotech.hw.fido2.exceptions.FidoClientPinInvalidException;
import de.cotech.hw.fido2.exceptions.FidoClientPinLastAttemptException;
import de.cotech.hw.fido2.internal.Fido2AppletConnection;
import de.cotech.hw.fido2.internal.ctap2.Ctap2Command;
import de.cotech.hw.fido2.internal.ctap2.Ctap2Exception;
import de.cotech.hw.fido2.internal.ctap2.CtapErrorResponse;
import de.cotech.hw.fido2.internal.ctap2.commands.clientPin.AuthenticatorClientPin;
import de.cotech.hw.fido2.internal.ctap2.commands.clientPin.AuthenticatorClientPinResponse;
import de.cotech.hw.util.Arrays;
import de.cotech.hw.util.Hex;
import de.cotech.hw.util.HwTimber;


public class PinProtocolV1 implements PinProtocol {
    public static final int PIN_PROTOCOL = 1;

    private final PinAuthCryptoUtil pinAuthCryptoUtil;

    public PinProtocolV1(PinAuthCryptoUtil pinAuthCryptoUtil) {
        this.pinAuthCryptoUtil = pinAuthCryptoUtil;
    }

    @Override
    public PinToken clientPinAuthenticate(
            Fido2AppletConnection fido2AppletConnection, String pin, boolean lastAttemptOk) throws IOException {
        AuthenticatorClientPin ctap2Command;
        AuthenticatorClientPinResponse authenticatorClientPinResponse;

        HwTimber.d("Authenticating with PIN");

        int retries;
        try {
            retries = checkRetries(fido2AppletConnection);
            if (retries == 0) {
                throw new FidoClientPinBlockedException();
            }
            if (retries == 1 && !lastAttemptOk) {
                throw new FidoClientPinLastAttemptException();
            }
        } catch (Ctap2Exception e) {
            if (e.ctapErrorResponse.errorCode() == CtapErrorResponse.CTAP2_ERR_PIN_BLOCKED) {
                throw new FidoClientPinBlockedException();
            }
            throw e;
        }

        ctap2Command = AuthenticatorClientPin.createGetKeyAgreement();
        authenticatorClientPinResponse = fido2AppletConnection.ctap2CommunicateOrThrow(ctap2Command);

        KeyPair platformKeyPair = pinAuthCryptoUtil.generatePlatformKeyPair();
        PrivateKey platformPrivateKey = platformKeyPair.getPrivate();
        PublicKey authenticatorPublicKey = pinAuthCryptoUtil.publicKeyFromCosePublicKey(authenticatorClientPinResponse.keyAgreement());

        byte[] sharedSecret = pinAuthCryptoUtil.generateSharedSecret(platformPrivateKey, authenticatorPublicKey);
        byte[] pinHashEnc = pinAuthCryptoUtil.calculatePinHashEnc(sharedSecret, pin);

        byte[] platformKeyAgreementKey = pinAuthCryptoUtil.cosePublicKeyFromPublicKey(platformKeyPair.getPublic());

        try {
            ctap2Command =
                    AuthenticatorClientPin.createGetPinToken(platformKeyAgreementKey, pinHashEnc);
            authenticatorClientPinResponse =
                    fido2AppletConnection.ctap2CommunicateOrThrow(ctap2Command);

            byte[] pinToken = pinAuthCryptoUtil
                    .decryptPinToken(sharedSecret, authenticatorClientPinResponse.pinToken());
            HwTimber.d("Authentication successful. pinToken is " +
                    Hex.encodeHexString(pinToken));
            return PinToken.create(this, pinToken, platformKeyAgreementKey, sharedSecret);
        } catch (Ctap2Exception e) {
            switch (e.ctapErrorResponse.errorCode()) {
                case CtapErrorResponse.CTAP2_ERR_PIN_BLOCKED:
                    throw new FidoClientPinBlockedException();
                case CtapErrorResponse.CTAP2_ERR_PIN_INVALID:
                    int retriesLeft = retries - 1;
                    throw new FidoClientPinInvalidException(retriesLeft);
            }
            throw e;
        }
    }

    @Override
    public int version() {
        return PIN_PROTOCOL;
    }

    private int checkRetries(Fido2AppletConnection fido2AppletConnection)
            throws IOException {
        Ctap2Command<AuthenticatorClientPinResponse> ctap2Command = AuthenticatorClientPin.createGetRetries();
        AuthenticatorClientPinResponse response = fido2AppletConnection.ctap2CommunicateOrThrow(ctap2Command);
        Integer retries = response.retries();
        if (retries == null) {
            throw new IOException("Failed to retrieve retries from authenticator.");
        }
        return retries;
    }

    public byte[] calculatePinAuth(PinToken pinToken, byte[] data) {
        return pinAuthCryptoUtil.calculatePinAuth(pinToken.pinToken(), data);
    }

    @Override
    public byte[] authenticate(PinToken pinToken, byte[] data) {
        return pinAuthCryptoUtil.authenticate(pinToken.sharedSecret(), data);
    }

    @Override
    public byte[] encrypt(PinToken pinToken, byte[] data) {
        return pinAuthCryptoUtil.encrypt(pinToken.sharedSecret(), data);
    }

    @Override
    public byte[] decrypt(PinToken pinToken, byte[] data) throws IOException {
        return pinAuthCryptoUtil.decrypt(pinToken.sharedSecret(), data);
    }
}
