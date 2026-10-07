import { SMSPacket, SMSFlagsBitmask, SMSInformationElement } from "./packet.js"
import { SMSEncoding } from "./encoding.js"

export function serialize(packet: SMSPacket): Uint8Array {
    const has_header = packet.elements.length > 0

    // Get size of TP-UDH (this is TP-UDHL)
    let header_size = packet.elements.length ? 
        packet.elements
            .map(e => e.value.length + 2)
            .reduce((a, b) => a + b)
        : 0

    // Get size of TP-UD (this is TP-UDL)
    let data_size = 0

    if (packet.encoding == SMSEncoding.GSM) {
        data_size = Math.ceil(((has_header ? header_size + 1 : 0) * 8) / 7) + Math.floor((packet.payload.length * 8) / 7)
    } else {
        // UTF8 and Unicode uses octets
        data_size = (has_header ? header_size + 1 : 0) + packet.payload.length
    }

    let size = (has_header ? header_size + 1 : 0) + packet.payload.length
    // TODO: Add 140 byte maximum limit

    // Construct serialized data
    const buffer = new Uint8Array(3 + size)

    // Byte 0 (Flags)
    // Bit 0-1 -> SUBMIT (0x01); Bit 6 -> set if UDH present
    buffer[0] = 0x01 | (has_header ? SMSFlagsBitmask.UDHI : 0x00);
    
    // Byte 1 (TP-DCS)
    buffer[1] = packet.encoding

    // Byte 2 (TP-UDL)
    buffer[2] = data_size

    // Bytes 3 to N (TP-UD)
    let offset = 3;

    if (has_header) {
        // TP-UDHL
        buffer[offset++] = header_size;

        // IEs
        for (const element of packet.elements) {
            buffer[offset++] = element.identifier & 0xFF // IEI
            buffer[offset++] = element.value.length & 0xFF // IE-DL
            buffer.set(element.value, offset); // IE-Data
            offset += element.value.length
        }
    }

    // TP-UD Message Payload
    buffer.set(packet.payload, offset)

    return buffer
}

export function deserialize(raw: Uint8Array): SMSPacket {
    // TODO: Add minimum 3-byte length

    const flags = raw[0]; // Flags
    const encoding = raw[1] as SMSEncoding; // TP-DCS
    const data_size = raw[2]; // TP-UDL

    const has_header = (flags & SMSFlagsBitmask.UDHI) !== 0
    const data = raw.subarray(3) // TP-UD
    
    // Get actual TP-UD data size
    let actual_data_size = 0;
    
    if (encoding === SMSEncoding.GSM) {
        actual_data_size = Math.ceil((data_size * 7) / 8)
    } else {
        actual_data_size = data_size
    }

    // TODO: Add guard for expected and actual size mismatch

    const bounded_data = data.subarray(0, actual_data_size)

    // Extract IE data
    const elements: SMSInformationElement[] = [];
    let payload_offset = 0;

    if (has_header) {
        // TODO: Add check for 0-length malformation
        
        const header_size = bounded_data[0] // TP-UDHL
        payload_offset = header_size + 1

        // TODO: Add offset and TP-UD length bounds check

        let element_offset = 1;
        while (element_offset < header_size + 1) {
            const identifier = bounded_data[element_offset] // IEI
            const element_size = bounded_data[element_offset + 1] // IE-DL
            const value = bounded_data.subarray(element_offset + 2, element_offset + 2 + element_size) // IE-Data

            elements.push({ identifier, value })
            element_offset += element_size + 2
        }
    }

    //  TP-UD Message Payload
    const payload = bounded_data.subarray(payload_offset)

    // Reconstruct Packet
    const packet = new SMSPacket(payload, {
        encoding,
        elements
    })

    return packet
}