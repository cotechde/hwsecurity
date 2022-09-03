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
import java.util.List;

import de.cotech.hw.fido2.PublicKeyCredential;
import de.cotech.hw.fido2.PublicKeyCredentialGet;
import de.cotech.hw.fido2.domain.CollectedClientData;
import de.cotech.hw.fido2.domain.PublicKeyCredentialDescriptor;
import de.cotech.hw.fido2.domain.PublicKeyCredentialUserEntity;
import de.cotech.hw.fido2.domain.UserVerificationRequirement;
import de.cotech.hw.fido2.domain.get.AssertionCreationData;
import de.cotech.hw.fido2.domain.get.AuthenticatorAssertionResponse;
import de.cotech.hw.fido2.domain.get.PublicKeyCredentialRequestOptions;
import de.cotech.hw.fido2.exceptions.FidoClientPinNotSetException;
import de.cotech.hw.fido2.exceptions.FidoClientPinNotSupportedException;
import de.cotech.hw.fido2.exceptions.FidoClientPinRequiredException;
import de.cotech.hw.fido2.exceptions.FidoInvalidCredentialException;
import de.cotech.hw.fido2.exceptions.FidoResidentKeyNoCredentialException;
import de.cotech.hw.fido2.exceptions.FidoResidentKeyNotSupportedException;
import de.cotech.hw.fido2.exceptions.FidoSecurityError;
import de.cotech.hw.fido2.internal.Fido2AppletConnection;
import de.cotech.hw.fido2.internal.cbor.CborPublicKeyCredentialDescriptorParser;
import de.cotech.hw.fido2.internal.cbor_java.model.UnicodeString;
import de.cotech.hw.fido2.internal.ctap2.Ctap2Exception;
import de.cotech.hw.fido2.internal.ctap2.CtapErrorResponse;
import de.cotech.hw.fido2.internal.ctap2.commands.getAssertion.AuthenticatorGetAssertion;
import de.cotech.hw.fido2.internal.ctap2.commands.getAssertion.AuthenticatorGetAssertionResponse;
import de.cotech.hw.fido2.internal.json.JsonCollectedClientDataSerializer;
import de.cotech.hw.fido2.internal.operations.WebauthnSecurityKeyOperation;
import de.cotech.hw.fido2.internal.pinauth.PinProtocolV1;
import de.cotech.hw.fido2.internal.pinauth.PinToken;
import de.cotech.hw.fido2.internal.utils.RelyingPartyIdUtils;
import de.cotech.hw.fido2.internal.webauthn.AuthenticatorDataParser;
import de.cotech.hw.util.HashUtil;
import de.cotech.hw.util.HwTimber;


public class AuthenticatorGetAssertionOperation extends
        WebauthnSecurityKeyOperation<PublicKeyCredential, PublicKeyCredentialGet> {
    private static final String CLIENT_DATA_TYPE_GET = "webauthn.get";

    private final CborPublicKeyCredentialDescriptorParser cborPublicKeyCredentialDescriptorParser;
    private final PinProtocolV1 pinProtocolV1;
    private final JsonCollectedClientDataSerializer jsonCollectedClientDataSerializer;
    private final RelyingPartyIdUtils relyingPartyIdUtils;
    private final AuthenticatorDataParser authenticatorDataParser = new AuthenticatorDataParser();

    public AuthenticatorGetAssertionOperation(
            CborPublicKeyCredentialDescriptorParser cborPublicKeyCredentialDescriptorParser,
            PinProtocolV1 pinProtocolV1,
            JsonCollectedClientDataSerializer jsonCollectedClientDataSerializer,
            RelyingPartyIdUtils relyingPartyIdUtils) {
        this.cborPublicKeyCredentialDescriptorParser = cborPublicKeyCredentialDescriptorParser;
        this.pinProtocolV1 = pinProtocolV1;
        this.jsonCollectedClientDataSerializer = jsonCollectedClientDataSerializer;
        this.relyingPartyIdUtils = relyingPartyIdUtils;
    }

    @Override
    public PublicKeyCredential performWebauthnSecurityKeyOperation(
            Fido2AppletConnection fido2AppletConnection,
            PublicKeyCredentialGet request)
    throws IOException {
        List<PublicKeyCredentialDescriptor> allowCredentials = request.options().allowCredentials();
        boolean isResidentKey = allowCredentials == null || allowCredentials.isEmpty();
        if (isResidentKey && !fido2AppletConnection.isSupportResidentKeys()) {
            throw new FidoResidentKeyNotSupportedException();
        }

        PinToken pinToken = acquirePinToken(fido2AppletConnection, request);
        AuthenticatorGetAssertion authenticatorGetAssertion = webauthnCommandToCtap2Command(request, pinToken);
        HwTimber.d(authenticatorGetAssertion.toString());
        try {
            AuthenticatorGetAssertionResponse response =
                    fido2AppletConnection.ctap2CommunicateOrThrow(authenticatorGetAssertion);

            return ctap2ResponseToWebauthnResponse(request, response);
        } catch (Ctap2Exception e) {
            switch (e.ctapErrorResponse.errorCode()) {
                case CtapErrorResponse.CTAP2_ERR_PIN_REQUIRED:
                    throw new FidoClientPinRequiredException();
                case CtapErrorResponse.CTAP2_ERR_INVALID_CREDENTIAL:
                case CtapErrorResponse.CTAP2_ERR_NO_CREDENTIALS: {
                    if (isResidentKey) {
                        throw new FidoResidentKeyNoCredentialException();
                    } else {
                        throw new FidoInvalidCredentialException();
                    }
                }
            }
            throw e;
        }
    }

    private PinToken acquirePinToken(
            Fido2AppletConnection fido2AppletConnection,
            PublicKeyCredentialGet request
    ) throws IOException {
        if (fido2AppletConnection.getCachedPinToken() != null) {
            return fido2AppletConnection.getCachedPinToken();
        }
        if (request.options().userVerification() == UserVerificationRequirement.REQUIRED) {
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

    public AuthenticatorGetAssertion webauthnCommandToCtap2Command(
            PublicKeyCredentialGet credentialGet, PinToken pinToken) throws FidoSecurityError {
        PublicKeyCredentialRequestOptions options = credentialGet.options();

        String origin = credentialGet.origin();
        String rpId = relyingPartyIdUtils.determineRelyingPartyId(origin, options.rpId());

        CollectedClientData collectedClientData =
                CollectedClientData.create(CLIENT_DATA_TYPE_GET, options.challenge(), origin, "SHA-256");
        String clientDataJson = jsonCollectedClientDataSerializer.clientClientDataToJson(collectedClientData);
        byte[] clientDataHash = HashUtil.sha256(clientDataJson);

        if (pinToken != null) {
            return AuthenticatorGetAssertion
                    .create(rpId, clientDataHash, clientDataJson, options.allowCredentials(), options.extensionParameters(), null,
                            pinToken);
        } else {
            return AuthenticatorGetAssertion.create(rpId, clientDataHash, clientDataJson, options.allowCredentials(), options.extensionParameters(), null);
        }
    }

    private PublicKeyCredential ctap2ResponseToWebauthnResponse(
            PublicKeyCredentialGet credentialGet,
            AuthenticatorGetAssertionResponse response
    ) throws IOException {
        byte[] credential = determinePublicKeyCredentialId(credentialGet, response);

        PublicKeyCredentialUserEntity user = response.user();
        AssertionCreationData assertionCreationData = AssertionCreationData.create(
                credential,
                response.clientDataJSON(),
                response.authData(),
                response.signature(),
                user != null ? user.id() : null
        );

        // Strictly following the spec, these next few lines belong in a ConstructAssertionAlg object.
        // However, they are really just copying data from AssertionCreationData, so we just do that
        // inline.
        AuthenticatorAssertionResponse authenticatorResponse = AuthenticatorAssertionResponse.create(
                assertionCreationData.clientDataJSONResult(),
                assertionCreationData.authenticatorDataResult(),
                assertionCreationData.signatureResult(),
                assertionCreationData.userHandleResult(),
                response.hmacSecretData()
        );
        return PublicKeyCredential
                .create(assertionCreationData.credentialIdResult(), authenticatorResponse);
    }

    private byte[] determinePublicKeyCredentialId(PublicKeyCredentialGet credentialCreate,
            AuthenticatorGetAssertionResponse response) throws IOException {
        byte[] credential;
        List<PublicKeyCredentialDescriptor> requestedCredentials =
                credentialCreate.options().allowCredentials();
        if (requestedCredentials != null && requestedCredentials.size() == 1) {
            credential = requestedCredentials.get(0).id();
        } else if (response.credential() != null) {
            Integer numberOfCredentials = response.numberOfCredentials();
            if (numberOfCredentials != null && numberOfCredentials > 1) {
                HwTimber.d("More than one credential returned, but not supported. Returning first.");
            }
            PublicKeyCredentialDescriptor publicKeyCredentialDescriptor =
                    cborPublicKeyCredentialDescriptorParser.parse(response.credential());
            credential = publicKeyCredentialDescriptor.id();
        } else {
            throw new IOException("Authenticator failed to transmit credential!");
        }
        return credential;
    }
}
