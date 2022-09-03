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

package de.cotech.hw.fido2.domain.get;


import androidx.annotation.Nullable;
import com.google.auto.value.AutoValue;
import de.cotech.hw.fido2.domain.AuthenticatorResponse;


@AutoValue
public abstract class AuthenticatorAssertionResponse extends AuthenticatorResponse {
    @SuppressWarnings("mutable")
    public abstract byte[] authenticatorData();
    @SuppressWarnings("mutable")
    public abstract byte[] signature();
    @Nullable
    @SuppressWarnings("mutable")
    public abstract byte[] userHandle();
    @Nullable
    @SuppressWarnings("mutable")
    public abstract byte[] hmacSecretData();

    public static AuthenticatorAssertionResponse create(byte[] clientDataJson, byte[] authenticatorData, byte[] signature, @Nullable byte[] userHandle, @Nullable byte[] hmacSecretData) {
        return new AutoValue_AuthenticatorAssertionResponse(clientDataJson, authenticatorData, signature, userHandle, hmacSecretData);
    }
}
