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


import androidx.annotation.Nullable;
import com.google.auto.value.AutoValue;
import de.cotech.hw.fido2.domain.PublicKeyCredentialUserEntity;
import de.cotech.hw.fido2.internal.ctap2.Ctap2Response;


@AutoValue
public abstract class AuthenticatorGetAssertionResponse extends Ctap2Response {
    // credential 	0x01 	definite length map (CBOR major type 5).
    @Nullable
    @SuppressWarnings("mutable")
    public abstract byte[] credential();
    // authData 	0x02 	byte string (CBOR major type 2).
    @SuppressWarnings("mutable")
    public abstract byte[] authData();
    // signature 	0x03 	byte string (CBOR major type 2).
    @SuppressWarnings("mutable")
    public abstract byte[] signature();
    // publicKeyCredentialUserEntity 	0x04 	definite length map (CBOR major type 5).
    @Nullable
    public abstract PublicKeyCredentialUserEntity user();
    // numberOfCredentials 	0x05 	unsigned integer(CBOR major type 0).
    @Nullable
    public abstract Integer numberOfCredentials();

    @SuppressWarnings("mutable")
    public abstract byte[] clientDataJSON();

    @Nullable
    @SuppressWarnings("mutable")
    public abstract byte[] hmacSecretData();


    public static AuthenticatorGetAssertionResponse create(
            @Nullable byte[] credential,
            byte[] authData,
            byte[] signature,
            @Nullable PublicKeyCredentialUserEntity user,
            @Nullable Integer numberOfCredentials,
            byte[] clientDataJSON,
            @Nullable byte[] hmacSecretData
    ) {
        return new AutoValue_AuthenticatorGetAssertionResponse(credential, authData, signature, user, numberOfCredentials, clientDataJSON, hmacSecretData);
    }
}
