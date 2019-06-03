/*
 * Copyright (C) 2018-2019 Confidential Technologies GmbH
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

package de.cotech.hw.pin;


import de.cotech.hw.bytesecret.ByteSecret;

/**
 * A trivial {@link PinProvider} that returns a static PIN.
 */
public class StaticPinProvider implements PinProvider {
    private ByteSecret pin;

    /**
     * Returns an instance of StaticPinProvider.
     *
     * @param pin the ByteSecret to statically return. Takes ownership of the passed ByteSecret.
     */
    public static StaticPinProvider getInstance(ByteSecret pin) {
        return new StaticPinProvider(pin.copy());
    }

    private StaticPinProvider(ByteSecret pin) {
        this.pin = pin;
    }

    @Override
    public ByteSecret getPin(byte[] securityKeyIdentifier) {
        return pin.copy();
    }
}
