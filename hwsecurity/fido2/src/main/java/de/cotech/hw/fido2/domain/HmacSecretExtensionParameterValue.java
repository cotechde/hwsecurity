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

package de.cotech.hw.fido2.domain;

import androidx.annotation.Nullable;

import com.google.auto.value.AutoValue;

@AutoValue
public abstract class HmacSecretExtensionParameterValue implements ExtensionParameter.ExtensionParameterValue {
    @SuppressWarnings("mutable")
    public abstract byte[] salt1();

    @Nullable
    @SuppressWarnings("mutable")
    public abstract byte[] salt2();

    public static HmacSecretExtensionParameterValue create(byte[] salt1, @Nullable byte[] salt2) {
        if (salt1.length != 32) {
            throw new IllegalArgumentException("HMAC salt1 must be 32 bytes in length exactly");
        }
        if (salt2 != null && salt2.length != 32) {
            throw new IllegalArgumentException("HMAC salt2 must be 32 bytes in length exactly");
        }
        return new AutoValue_HmacSecretExtensionParameterValue(salt1, salt2);
    }
}
