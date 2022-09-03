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

package de.cotech.hw.fido2.internal.ctap2.commands.makeCredential;


import java.util.List;

import androidx.annotation.Nullable;
import com.google.auto.value.AutoValue;

import de.cotech.hw.fido2.domain.ExtensionParameter;
import de.cotech.hw.fido2.internal.ctap2.Ctap2Command;
import de.cotech.hw.fido2.domain.PublicKeyCredentialDescriptor;
import de.cotech.hw.fido2.domain.PublicKeyCredentialParameters;
import de.cotech.hw.fido2.domain.PublicKeyCredentialRpEntity;
import de.cotech.hw.fido2.domain.PublicKeyCredentialUserEntity;
import de.cotech.hw.fido2.internal.ctap2.Ctap2ResponseFactory;


@AutoValue
public abstract class AuthenticatorMakeCredential extends Ctap2Command<AuthenticatorMakeCredentialResponse> {
    // 	Byte Array 	Required 	Hash of the ClientData contextual binding specified by host. See [WebAuthN].
    @SuppressWarnings("mutable")
    public abstract byte[] clientDataHash();

    // Out of spec: The clientDataJson object associated with this request
    public abstract String clientDataJson();

    // 	PublicKeyCredentialRpEntity 	Required 	This PublicKeyCredentialRpEntity data structure describes a Relying Party with which the new public key credential will be associated. It contains the Relying party identifier, (optionally) a human-friendly RP name, and (optionally) a URL referencing a RP icon image. The RP name is to be used by the authenticator when displaying the credential to the user for selection and usage authorization.
    public abstract PublicKeyCredentialRpEntity rp();

    // 	PublicKeyCredentialUserEntity 	Required 	This PublicKeyCredentialUserEntity data structure describes the user account to which the new public key credential will be associated at the RP. It contains an RP-specific user account identifier, (optionally) a user name, (optionally) a user display name, and (optionally) a URL referencing a user icon image (of a user avatar, for example). The authenticator associates the created public key credential with the account identifier, and MAY also associate any or all of the user name, user display name, and image data (pointed to by the URL, if any).
    public abstract PublicKeyCredentialUserEntity user();

    // 	CBOR Array 	Required 	A sequence of CBOR maps consisting of pairs of PublicKeyCredentialType (a string) and cryptographic algorithm (a positive or negative integer), where algorithm identifiers are values that SHOULD be registered in the IANA COSE Algorithms registry [IANA-COSE-ALGS-REG]. This sequence is ordered from most preferred (by the RP) to least preferred.
    public abstract List<PublicKeyCredentialParameters> pubKeyCredParams();

    // 	Sequence of PublicKeyCredentialDescriptors 	Optional 	A sequence of PublicKeyCredentialDescriptor structures, as specified in [WebAuthN]. The authenticator returns an error if the authenticator already contains one of the credentials enumerated in this sequence. This allows RPs to limit the creation of multiple credentials for the same account on a single authenticator.
    @Nullable
    public abstract List<PublicKeyCredentialDescriptor> excludeList();

    // 	CBOR map of extension identifier → authenticator extension input values 	Optional 	Parameters to influence authenticator operation, as specified in [WebAuthN]. These parameters might be authenticator specific.
    @Nullable
    public abstract List<ExtensionParameter> extensions();

    // Map of authenticator options 	Optional 	Parameters to influence authenticator operation, as specified in in the table below.
    @Nullable
    public abstract AuthenticatorMakeCredentialOptions options();

    // Byte Array 	Optional 	First 16 bytes of HMAC-SHA-256 of clientDataHash using pinToken which platform got from the authenticator: HMAC-SHA-256(pinToken, clientDataHash).
    @Nullable
    @SuppressWarnings("mutable")
    public abstract byte[] pinAuth();

    // Unsigned Integer 	Optional 	PIN protocol version chosen by the client
    @Nullable
    public abstract Integer pinProtocol();

    @AutoValue
    public static abstract class AuthenticatorMakeCredentialOptions {
        @Nullable
        public abstract Boolean rk();
        @Nullable
        public abstract Boolean uv();

        public static AuthenticatorMakeCredentialOptions create(Boolean rk, Boolean uv) {
            return new AutoValue_AuthenticatorMakeCredential_AuthenticatorMakeCredentialOptions(rk, uv);
        }
    }

    @Override
    public Ctap2ResponseFactory<AuthenticatorMakeCredentialResponse> getResponseFactory() {
        return new AuthenticatorMakeCredentialResponseFactory(this);
    }

    public static AuthenticatorMakeCredential create(
            byte[] clientDataHash, String clientDataJson, PublicKeyCredentialRpEntity rp, PublicKeyCredentialUserEntity user) {
        return create(clientDataHash, clientDataJson, rp, user, PublicKeyCredentialParameters.createDefaultEs256List(),
                null, null, null, null);
    }

    public static AuthenticatorMakeCredential create(byte[] clientDataHash, String clientDataJson,
            PublicKeyCredentialRpEntity rp, PublicKeyCredentialUserEntity user, List<PublicKeyCredentialParameters> pubKeyCredParams) {
        return create(clientDataHash, clientDataJson, rp, user, pubKeyCredParams, null, null, null, null);
    }

    public static AuthenticatorMakeCredential create(byte[] clientDataHash, String clientDataJson,
            PublicKeyCredentialRpEntity rp, PublicKeyCredentialUserEntity user, List<PublicKeyCredentialParameters> pubKeyCredParams,
            List<PublicKeyCredentialDescriptor> excludeList) {
        return create(clientDataHash, clientDataJson, rp, user, pubKeyCredParams, excludeList, null, null, null);
    }

    public static AuthenticatorMakeCredential create(byte[] clientDataHash, String clientDataJson,
            PublicKeyCredentialRpEntity rp, PublicKeyCredentialUserEntity user, List<PublicKeyCredentialParameters> pubKeyCredParams,
            List<PublicKeyCredentialDescriptor> excludeList,
            AuthenticatorMakeCredentialOptions options, byte[] pinAuth, Integer pinProtocol) {
        return new AutoValue_AuthenticatorMakeCredential(Ctap2Command.COMMAND_MAKE_CREDENTIAL, clientDataHash, clientDataJson, rp, user,
                pubKeyCredParams, excludeList, null, options, pinAuth, pinProtocol);
    }

    public static AuthenticatorMakeCredential create(byte[] clientDataHash, String clientDataJson,
                                                     PublicKeyCredentialRpEntity rp, PublicKeyCredentialUserEntity user, List<PublicKeyCredentialParameters> pubKeyCredParams,
                                                     List<PublicKeyCredentialDescriptor> excludeList,
                                                     List<ExtensionParameter> extensionParameters,
                                                     AuthenticatorMakeCredentialOptions options, byte[] pinAuth, Integer pinProtocol) {
        return new AutoValue_AuthenticatorMakeCredential(Ctap2Command.COMMAND_MAKE_CREDENTIAL, clientDataHash, clientDataJson, rp, user,
                pubKeyCredParams, excludeList, extensionParameters, options, pinAuth, pinProtocol);
    }
}
