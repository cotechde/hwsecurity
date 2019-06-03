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

package de.cotech.hw.internal.transport.usb.ccid.tpdu;


import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;

import de.cotech.hw.internal.transport.usb.ccid.CcidTransceiver;
import de.cotech.hw.internal.transport.usb.ccid.CcidTransceiver.CcidDataBlock;
import de.cotech.hw.internal.transport.usb.ccid.CcidTransportProtocol;
import de.cotech.hw.internal.transport.usb.UsbTransportException;

@RestrictTo(Scope.LIBRARY_GROUP)
public class T1ShortApduProtocol implements CcidTransportProtocol {
    private CcidTransceiver ccidTransceiver;

    public void connect(@NonNull CcidTransceiver transceiver) throws UsbTransportException {
        ccidTransceiver = transceiver;
        ccidTransceiver.iccPowerOn();
    }

    @Override
    public byte[] transceive(@NonNull final byte[] apdu) throws UsbTransportException {
        CcidDataBlock response = ccidTransceiver.sendXfrBlock(apdu);
        return response.getData();
    }
}
