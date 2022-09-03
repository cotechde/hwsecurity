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

package de.cotech.hw.fido2.internal.operations.ctap2;


import java.io.IOException;

import de.cotech.hw.fido2.PublicKeyCredential;
import de.cotech.hw.fido2.PublicKeyCredentialCreate;
import de.cotech.hw.fido2.domain.CollectedClientData;
import de.cotech.hw.fido2.domain.PublicKeyCredentialRpEntity;
import de.cotech.hw.fido2.domain.UserVerificationRequirement;
import de.cotech.hw.fido2.domain.create.AttestationObject;
import de.cotech.hw.fido2.domain.create.CredentialCreationData;
import de.cotech.hw.fido2.domain.create.PublicKeyCredentialCreationOptions;
import de.cotech.hw.fido2.exceptions.FidoClientPinNotSetException;
import de.cotech.hw.fido2.exceptions.FidoClientPinNotSupportedException;
import de.cotech.hw.fido2.exceptions.FidoClientPinRequiredException;
import de.cotech.hw.fido2.exceptions.FidoSecurityError;
import de.cotech.hw.fido2.internal.Fido2AppletConnection;
import de.cotech.hw.fido2.internal.ctap2.Ctap2Exception;
import de.cotech.hw.fido2.internal.ctap2.CtapErrorResponse;
import de.cotech.hw.fido2.internal.ctap2.commands.makeCredential.AuthenticatorMakeCredential;
import de.cotech.hw.fido2.internal.ctap2.commands.makeCredential.AuthenticatorMakeCredential.AuthenticatorMakeCredentialOptions;
import de.cotech.hw.fido2.internal.ctap2.commands.makeCredential.AuthenticatorMakeCredentialResponse;
import de.cotech.hw.fido2.internal.json.JsonCollectedClientDataSerializer;
import de.cotech.hw.fido2.internal.operations.WebauthnSecurityKeyOperation;
import de.cotech.hw.fido2.internal.pinauth.PinProtocolV1;
import de.cotech.hw.fido2.internal.pinauth.PinToken;
import de.cotech.hw.fido2.internal.utils.RelyingPartyIdUtils;
import de.cotech.hw.fido2.internal.webauthn.ConstructCredentialAlg;
import de.cotech.hw.util.HashUtil;
import de.cotech.hw.util.HwTimber;


public class AuthenticatorMakeCredentialOperation extends
        WebauthnSecurityKeyOperation<PublicKeyCredential, PublicKeyCredentialCreate> {
    private static final String CLIENT_DATA_TYPE_CREATE = "webauthn.create";
    private final ConstructCredentialAlg constructCredentialAlg;
    private final PinProtocolV1 pinProtocolV1;
    private final RelyingPartyIdUtils relyingPartyIdUtils;

    public AuthenticatorMakeCredentialOperation(
            ConstructCredentialAlg constructCredentialAlg,
            PinProtocolV1 pinProtocolV1,
            RelyingPartyIdUtils relyingPartyIdUtils) {
        this.constructCredentialAlg = constructCredentialAlg;
        this.pinProtocolV1 = pinProtocolV1;
        this.relyingPartyIdUtils = relyingPartyIdUtils;
    }

    @Override
    public PublicKeyCredential performWebauthnSecurityKeyOperation(
            Fido2AppletConnection fido2AppletConnection,
            PublicKeyCredentialCreate request) throws IOException {
        PinToken pinToken = acquirePinToken(fido2AppletConnection, request);
        AuthenticatorMakeCredential authenticatorMakeCredential = webauthnToCtap2Command(request, pinToken);
        HwTimber.d(authenticatorMakeCredential.toString());
        try {
            AuthenticatorMakeCredentialResponse response =
                    fido2AppletConnection.ctap2CommunicateOrThrow(authenticatorMakeCredential);
            return ctap2ToWebauthnResponse(request, response);
        } catch (Ctap2Exception e) {
            switch (e.ctapErrorResponse.errorCode()) {
                case CtapErrorResponse.CTAP2_ERR_PIN_REQUIRED:
                    throw new FidoClientPinRequiredException();
            }
            throw e;
        }
    }

    private PinToken acquirePinToken(
            Fido2AppletConnection fido2AppletConnection,
            PublicKeyCredentialCreate request
    ) throws IOException {
        if (fido2AppletConnection.getCachedPinToken() != null) {
            return fido2AppletConnection.getCachedPinToken();
        }
        if (request.options().authenticatorSelection().userVerification() == UserVerificationRequirement.REQUIRED) {
            if (!fido2AppletConnection.isSupportClientPin()) {
                throw new FidoClientPinNotSupportedException();
            }
            if (!fido2AppletConnection.isClientPinSet()) {
                throw new FidoClientPinNotSetException();
            }
            if (request.clientPin() == null) {
                throw new FidoClientPinRequiredException();
            }
        }
        if (request.clientPin() == null || !fido2AppletConnection.isSupportClientPin() || !fido2AppletConnection.isClientPinSet()) {
            return null;
        }

        PinToken pinToken = pinProtocolV1.clientPinAuthenticate(fido2AppletConnection, request.clientPin(), request.lastAttemptOk());
        fido2AppletConnection.setCachedPinToken(pinToken);
        return pinToken;
    }

    public AuthenticatorMakeCredential webauthnToCtap2Command(
            PublicKeyCredentialCreate credentialCreate, PinToken pinToken)
            throws FidoSecurityError {
        PublicKeyCredentialCreationOptions options = credentialCreate.options();

        PublicKeyCredentialRpEntity rp = options.rp();
        String origin = credentialCreate.origin();
        String rpId = relyingPartyIdUtils.determineRelyingPartyId(origin, rp.id());
        rp = rp.withId(rpId);

        CollectedClientData collectedClientData =
                CollectedClientData.create(CLIENT_DATA_TYPE_CREATE, options.challenge(), credentialCreate.origin(), "SHA-256");
        String clientDataJson = new JsonCollectedClientDataSerializer().clientClientDataToJson(collectedClientData);
        byte[] clientDataHash = HashUtil.sha256(clientDataJson);

        AuthenticatorMakeCredentialOptions authenticatorOptions;
        boolean requireResidentKey = options.authenticatorSelection().requireResidentKey();
        // this is the only supported option so far. only set options if it is set
        if (requireResidentKey) {
            authenticatorOptions = AuthenticatorMakeCredentialOptions.create(true, false);
        } else {
            authenticatorOptions = null;
        }

        if (pinToken != null) {
            byte[] pinAuth = pinToken.calculatePinAuth(clientDataHash);
            return AuthenticatorMakeCredential.create(clientDataHash, clientDataJson, rp, options.user(), options.pubKeyCredParams(),
                    options.excludeCredentials(), options.extensionParameters(), authenticatorOptions, pinAuth, pinToken.pinProtocol().version());
        } else {
            return AuthenticatorMakeCredential.create(clientDataHash, clientDataJson, rp, options.user(), options.pubKeyCredParams(),
                    options.excludeCredentials(), options.extensionParameters(), authenticatorOptions, null, null);
        }
    }

    private PublicKeyCredential ctap2ToWebauthnResponse(
            PublicKeyCredentialCreate credentialCreate,
            AuthenticatorMakeCredentialResponse response
    ) throws IOException {
        CredentialCreationData credentialCreationData = CredentialCreationData.create(
                AttestationObject.create(response.fmt(), response.authData(), response.attStmt()),
                response.clientDataJSON(),
                credentialCreate.options().attestation()
        );
        return constructCredentialAlg.publicKeyCredential(credentialCreationData);
    }
}
