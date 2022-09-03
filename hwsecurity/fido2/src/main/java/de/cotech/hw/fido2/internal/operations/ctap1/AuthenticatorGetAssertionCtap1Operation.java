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

package de.cotech.hw.fido2.internal.operations.ctap1;


import java.io.IOException;
import java.util.List;

import de.cotech.hw.fido2.PublicKeyCredential;
import de.cotech.hw.fido2.PublicKeyCredentialGet;
import de.cotech.hw.fido2.domain.PublicKeyCredentialDescriptor;
import de.cotech.hw.fido2.domain.create.AuthenticatorData;
import de.cotech.hw.fido2.domain.get.AuthenticatorAssertionResponse;
import de.cotech.hw.fido2.exceptions.FidoWrongKeyHandleException;
import de.cotech.hw.fido2.internal.Fido2AppletConnection;
import de.cotech.hw.fido2.internal.Fido2CommandApduFactory;
import de.cotech.hw.fido2.internal.ctap2.commands.getAssertion.AuthenticatorGetAssertion;
import de.cotech.hw.fido2.internal.operations.WebauthnSecurityKeyOperation;
import de.cotech.hw.fido2.internal.operations.ctap2.AuthenticatorGetAssertionOperation;
import de.cotech.hw.fido2.internal.webauthn.AuthenticatorDataParser;
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.internal.iso7816.ResponseApdu;
import de.cotech.hw.util.Arrays;
import de.cotech.hw.util.HashUtil;
import de.cotech.hw.util.HwTimber;


public class AuthenticatorGetAssertionCtap1Operation extends
        WebauthnSecurityKeyOperation<PublicKeyCredential, PublicKeyCredentialGet> {
    private final AuthenticatorGetAssertionOperation ctap2Operation;
    private final Fido2CommandApduFactory fido2CommandApduFactory = new Fido2CommandApduFactory();

    public AuthenticatorGetAssertionCtap1Operation(
            AuthenticatorGetAssertionOperation ctap2Operation) {
        this.ctap2Operation = ctap2Operation;
    }

    @Override
    public PublicKeyCredential performWebauthnSecurityKeyOperation(
            Fido2AppletConnection fido2AppletConnection,
            PublicKeyCredentialGet request)
            throws IOException {
        AuthenticatorGetAssertion authenticatorGetAssertion =
                ctap2Operation.webauthnCommandToCtap2Command(request, null);
        byte[] rpIdHash = HashUtil.sha256(authenticatorGetAssertion.rpId());

        List<PublicKeyCredentialDescriptor> allowedCredentials =
                authenticatorGetAssertion.allowList();
        for (int i = 0, count = allowedCredentials.size(); i < count; i++) {
            try {
                PublicKeyCredentialDescriptor credential = allowedCredentials.get(i);
                HwTimber.i("Attempting credentials (%d/%d): %s", i+1, count, credential);
                return attemptU2fAuthentication(fido2AppletConnection, authenticatorGetAssertion,
                        rpIdHash, credential);
            } catch (FidoWrongKeyHandleException e) {
                HwTimber.d("Key handle rejected");
            }
        }

        // CtapErrorResponse.create(CtapErrorResponse.CTAP2_ERR_NO_CREDENTIALS);
        throw new IOException("No valid credentials provided!");
    }

    private PublicKeyCredential attemptU2fAuthentication(
            Fido2AppletConnection fido2AppletConnection,
            AuthenticatorGetAssertion authenticatorGetAssertion, byte[] rpIdHash,
            PublicKeyCredentialDescriptor publicKeyCredentialDescriptor) throws IOException {
        CommandApdu authenticationCommand = createCtap1CommandApdu(
                authenticatorGetAssertion.clientDataHash(), rpIdHash, publicKeyCredentialDescriptor.id());
        ResponseApdu responseApdu = fido2AppletConnection.communicateOrThrow(authenticationCommand);
        return ctap1ResponseApduToWebauthnResponse(authenticatorGetAssertion, publicKeyCredentialDescriptor, rpIdHash, responseApdu);
    }

    private CommandApdu createCtap1CommandApdu(
            byte[] challengeParam, byte[] applicationParam, byte[] keyHandle) {
        byte[] keyHandleLength = new byte[] { (byte) keyHandle.length };
        byte[] payload = Arrays.concatenate(challengeParam, applicationParam, keyHandleLength, keyHandle);
        return fido2CommandApduFactory.createAuthenticationCommand(payload);
    }

    private PublicKeyCredential ctap1ResponseApduToWebauthnResponse(
            AuthenticatorGetAssertion authenticatorGetAssertion,
            PublicKeyCredentialDescriptor publicKeyCredentialDescriptor, byte[] rpIdHash,
            ResponseApdu responseApdu) throws IOException {
        byte[] responseData = responseApdu.getData();
        U2fAuthenticateResponse u2fResponse = U2fAuthenticateResponse.fromBytes(responseData);

        AuthenticatorData authenticatorData =
                AuthenticatorData.create(rpIdHash, u2fResponse.presence(), u2fResponse.counter(), null, null);
        byte[] authenticatorDataBytes = new AuthenticatorDataParser().toBytes(authenticatorData);
        AuthenticatorAssertionResponse authenticatorResponse =
                AuthenticatorAssertionResponse.create(
                        authenticatorGetAssertion.clientDataJson().getBytes(),
                        authenticatorDataBytes,
                        u2fResponse.signature(),
                        null,
                        null
                );

        return PublicKeyCredential.create(publicKeyCredentialDescriptor.id(), authenticatorResponse);
    }
}
