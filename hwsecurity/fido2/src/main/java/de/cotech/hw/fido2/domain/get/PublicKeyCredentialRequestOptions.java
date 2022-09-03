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


import java.util.List;

import android.os.Parcelable;

import androidx.annotation.Nullable;
import com.google.auto.value.AutoValue;

import de.cotech.hw.fido2.domain.ExtensionParameter;
import de.cotech.hw.fido2.domain.PublicKeyCredentialDescriptor;
import de.cotech.hw.fido2.domain.UserVerificationRequirement;


@AutoValue
public abstract class PublicKeyCredentialRequestOptions implements Parcelable {
    @SuppressWarnings("mutable")
    public abstract byte[] challenge();
    @Nullable
    public abstract Long timeout();
    @Nullable
    public abstract String rpId();
    @Nullable
    public abstract List<PublicKeyCredentialDescriptor> allowCredentials();
    @Nullable
    public abstract UserVerificationRequirement userVerification();
    @Nullable
    public abstract List<ExtensionParameter> extensionParameters();

    public static PublicKeyCredentialRequestOptions create(
            byte[] challenge,
            Long timeout,
            String rpId,
            List<PublicKeyCredentialDescriptor> allowCredentials,
            UserVerificationRequirement userVerification
    ) {
        return create(challenge, timeout, rpId, allowCredentials, userVerification, null);
    }

    public static PublicKeyCredentialRequestOptions create(
            byte[] challenge,
            Long timeout,
            String rpId,
            List<PublicKeyCredentialDescriptor> allowCredentials,
            UserVerificationRequirement userVerification,
            @Nullable
            List<ExtensionParameter> extensionParameters
    ) {
        return new AutoValue_PublicKeyCredentialRequestOptions(
                challenge, timeout, rpId, allowCredentials, userVerification,
                extensionParameters);
    }
}
