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

package de.cotech.hw.internal.transport.usb.u2fhid;


import java.io.IOException;
import java.util.List;

import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.os.SystemClock;
import android.util.Pair;

import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.internal.iso7816.ResponseApdu;
import de.cotech.hw.internal.transport.SecurityKeyInfo.SecurityKeyType;
import de.cotech.hw.internal.transport.SecurityKeyInfo.TransportType;
import de.cotech.hw.internal.transport.Transport;
import de.cotech.hw.internal.transport.usb.UsbSecurityKeyTypes;
import de.cotech.hw.internal.transport.usb.UsbTransportException;
import de.cotech.hw.internal.transport.usb.UsbUtils;
import de.cotech.hw.util.Hex;
import timber.log.Timber;


/**
 * USB U2FHID
 * https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html
 */
@RestrictTo(Scope.LIBRARY_GROUP)
public class UsbU2fHidTransport implements Transport {
    private static final List<String> HID_REPORT_FIDO_PREFIXES = java.util.Arrays.asList("06d0f10901", "06d0f10a0100");

    private final UsbDevice usbDevice;
    private final UsbDeviceConnection usbConnection;
    private final UsbInterface usbInterface;
    private boolean enableDebugLogging;
    private U2fHidTransportProtocol u2fHidTransportProtocol;

    private boolean released = false;
    private TransportReleasedCallback transportReleasedCallback;

    public static UsbU2fHidTransport createUsbTransport(UsbDevice usbDevice, UsbDeviceConnection usbConnection,
                                                 UsbInterface usbInterface, boolean enableDebugLogging) {
        return new UsbU2fHidTransport(usbDevice, usbConnection, usbInterface, enableDebugLogging);
    }

    private UsbU2fHidTransport(UsbDevice usbDevice, UsbDeviceConnection usbConnection, UsbInterface usbInterface,
                               boolean enableDebugLogging) {
        this.usbDevice = usbDevice;
        this.usbConnection = usbConnection;
        this.usbInterface = usbInterface;
        this.enableDebugLogging = enableDebugLogging;
    }

    /**
     * Check if device is was connected to and still is connected
     *
     * @return true if device is connected
     */
    @Override
    public boolean isConnected() {
        return u2fHidTransportProtocol != null && !released;
    }

    @Override
    public boolean isReleased() {
        return released;
    }

    @Override
    public void setTransportReleaseCallback(TransportReleasedCallback callback) {
        this.transportReleasedCallback = callback;
    }

    /**
     * Check if Transport supports persistent connections e.g connections which can
     * handle multiple operations in one session
     *
     * @return true if transport supports persistent connections
     */
    @Override
    public boolean isPersistentConnectionAllowed() {
        return true;
    }

    /**
     * Connect to OTG device
     */
    @Override
    public void connect() throws IOException {
        if (u2fHidTransportProtocol != null) {
            throw new IllegalStateException("Already connected!");
        }

        Pair<UsbEndpoint, UsbEndpoint> ioEndpoints = UsbUtils.getIoEndpoints(
                usbInterface, UsbConstants.USB_ENDPOINT_XFER_INT);
        UsbEndpoint usbIntIn = ioEndpoints.first;
        UsbEndpoint usbIntOut = ioEndpoints.second;

        if (usbIntIn == null || usbIntOut == null) {
            throw new UsbTransportException("USB_U2FHID error: invalid class 3 interface");
        }

        checkHidReportPrefix();

        U2fHidTransportProtocol u2fHidTransportProtocol =
                new U2fHidTransportProtocol(usbConnection, usbIntIn, usbIntOut);
        u2fHidTransportProtocol.connect();
        this.u2fHidTransportProtocol = u2fHidTransportProtocol;
    }

    private void checkHidReportPrefix() throws IOException {
        byte[] hidReportDescriptor = UsbUtils.requestHidReportDescriptor(usbConnection, usbInterface.getId());
        String hidReportDescriptorHex = Hex.encodeHexString(hidReportDescriptor);
        for (String prefix : HID_REPORT_FIDO_PREFIXES) {
            if (hidReportDescriptorHex.startsWith(prefix)) {
                return;
            }
        }
        throw new IOException("HID descriptor prefix didn't match expected FIDO UsagePage and Usage!");
    }

    /**
     * Transmit and receive data
     *
     * @param commandApdu data to transmit
     * @return received data
     */
    @Override
    public ResponseApdu transceive(CommandApdu commandApdu) throws IOException {
        if (released) {
            throw new UsbTransportException("Transport is no longer available!");
        }

        // "For the U2FHID protocol, all raw U2F messages are encoded using extended length APDU encoding."
        // https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html
        // This will already be the case for some APDUs, see FidoU2fAppletConnection
        CommandApdu extendedCommandApdu = commandApdu.withNe(65536);

        if (enableDebugLogging) {
            Timber.d("U2FHID out: %s", extendedCommandApdu);
        }

        long startRealtime = SystemClock.elapsedRealtime();
        byte[] rawResponse = u2fHidTransportProtocol.transceive(extendedCommandApdu.toBytes());

        ResponseApdu responseApdu = ResponseApdu.fromBytes(rawResponse);
        if (enableDebugLogging) {
            long totalTime = SystemClock.elapsedRealtime() - startRealtime;
            Timber.d("U2FHID in: %s", responseApdu);
            Timber.d("U2FHID communication took %dms", totalTime);
        }

        return responseApdu;
    }

    @Override
    public boolean isExtendedLengthSupported() {
        return true;
    }

    @Override
    public void release() {
        if (!released) {
            Timber.d("Usb transport disconnected");
            this.released = true;
            usbConnection.releaseInterface(usbInterface);
            if (transportReleasedCallback != null) {
                transportReleasedCallback.onTransportReleased();
            }
        }
    }

    @Override
    public TransportType getTransportType() {
        return TransportType.USB_U2FHID;
    }

    @Override
    public boolean ping() {
        return !released;
    }

    @Nullable
    @Override
    public SecurityKeyType getSecurityKeyTypeIfAvailable() {
        return UsbSecurityKeyTypes.getSecurityKeyTypeFromUsbDeviceInfo(
                usbDevice.getVendorId(), usbDevice.getProductId(), usbConnection.getSerial());
    }
}
