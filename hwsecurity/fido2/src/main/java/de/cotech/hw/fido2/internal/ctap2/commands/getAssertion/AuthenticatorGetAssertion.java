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

package de.cotech.hw.fido2.internal.ctap2.commands.getAssertion;


import java.util.List;

import androidx.annotation.Nullable;
import com.google.auto.value.AutoValue;

import de.cotech.hw.fido2.domain.ExtensionParameter;
import de.cotech.hw.fido2.domain.PublicKeyCredentialDescriptor;
import de.cotech.hw.fido2.internal.ctap2.Ctap2Command;
import de.cotech.hw.fido2.internal.ctap2.Ctap2ResponseFactory;
import de.cotech.hw.fido2.internal.ctap2.commands.getInfo.AuthenticatorOptions;
import de.cotech.hw.fido2.internal.pinauth.PinToken;


@AutoValue
public abstract class AuthenticatorGetAssertion extends Ctap2Command<AuthenticatorGetAssertionResponse> {
    // rpId 	0x01 	UTF-8 encoded text string (CBOR major type 3).
    public abstract String rpId();
    // clientDataHash 	0x02 	byte string (CBOR major type 2).
    @SuppressWarnings("mutable")
    public abstract byte[] clientDataHash();
    // Out of spec: The clientDataJson object associated with this request
    public abstract String clientDataJson();
    // allowList 	0x03 	CBOR definite length array (CBOR major type 4) of CBOR definite length maps (CBOR major type 5).
    @Nullable
    public abstract List<PublicKeyCredentialDescriptor> allowList();
    // extensions 	0x04 	CBOR definite length map (CBOR major type 5).
    @Nullable
    @SuppressWarnings("mutable")
    public abstract List<ExtensionParameter> extensions();
    // options 	0x05 	CBOR definite length map (CBOR major type 5).
    @Nullable
    abstract AuthenticatorOptions options();
    // pinAuth 	0x06 	byte string (CBOR major type 2).
    @Nullable
    @SuppressWarnings("mutable")
    public abstract byte[] pinAuth();
    // pinProtocol 	0x07 	PIN protocol version chosen by the client. For this version of the spec, this SHALL be the number 1.
    @Nullable
    public abstract Integer pinProtocol();
    // Out of spec: The pinToken object associated with this request
    @Nullable
    public abstract PinToken pinToken();

    public static AuthenticatorGetAssertion create(String rpId, byte[] clientDataHash, String clientDataJson, List<PublicKeyCredentialDescriptor> allowCredentials, AuthenticatorOptions options) {
        return new AutoValue_AuthenticatorGetAssertion(COMMAND_GET_ASSERTION, rpId, clientDataHash, clientDataJson, allowCredentials, null, options, null, null, null);
    }

    public static AuthenticatorGetAssertion create(String rpId, byte[] clientDataHash, String clientDataJson, List<PublicKeyCredentialDescriptor> allowCredentials, List<ExtensionParameter> extensionParameters, AuthenticatorOptions options) {
        return new AutoValue_AuthenticatorGetAssertion(COMMAND_GET_ASSERTION, rpId, clientDataHash, clientDataJson, allowCredentials, extensionParameters, options, null, null, null);
    }

    public static AuthenticatorGetAssertion create(String rpId, byte[] clientDataHash, String clientDataJson, List<PublicKeyCredentialDescriptor> allowCredentials, AuthenticatorOptions options, PinToken pinToken) {
        byte[] pinAuth = pinToken.calculatePinAuth(clientDataHash);
        return new AutoValue_AuthenticatorGetAssertion(COMMAND_GET_ASSERTION, rpId, clientDataHash, clientDataJson, allowCredentials, null, options, pinAuth, pinToken.pinProtocol().version(), pinToken);
    }

    public static AuthenticatorGetAssertion create(String rpId, byte[] clientDataHash, String clientDataJson, List<PublicKeyCredentialDescriptor> allowCredentials, List<ExtensionParameter> extensionParameters, AuthenticatorOptions options, PinToken pinToken) {
        byte[] pinAuth = pinToken.calculatePinAuth(clientDataHash);
        return new AutoValue_AuthenticatorGetAssertion(COMMAND_GET_ASSERTION, rpId, clientDataHash, clientDataJson, allowCredentials, extensionParameters, options, pinAuth, pinToken.pinProtocol().version(), pinToken);
    }

    @Override
    public Ctap2ResponseFactory<AuthenticatorGetAssertionResponse> getResponseFactory() {
        return new AuthenticatorGetAssertionResponseFactory(this);
    }
}
