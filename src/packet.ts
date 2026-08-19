/*
    SMS Packet / Frame (formally "PDU (Protocol Data Unit)" as per ETSI 3GPP SMS TS 23.040 V18.0.0)
    
    This amateur packet "specification" aims to mimic the actual SMS packet specification
    as per ETSI TS 23.040 V18.0.0, albeit heavily stripped out of its elements, thus only
    including minimal elements required for the protocol to run on the simulator.

    <--- START --->

    The binary layout of the packet is as follows, in big-endian:
    Byte 0 -> First Octet (Flags)
    Byte 1 -> TP-DCS (Data Coding Scheme)
    Byte 2 -> TP-UDL (User Data Length)
    Byte 3 to N -> TP-UD


    First Octet (Byte 0)
    - This is the octet that contains all relevant flags.

       Bit 7   Bit 6    Bit 5    Bit 4   Bit 3   Bit 2   Bit 1   Bit 0
    +-------+---------+--------+-------+-------+-------+-------+-------+
    | TP-RP | TP-UDHI | TP-SRR |     TP-VPF    | TP-RD |    TP-MTI     |
    +-------+---------+--------+-------+-------+-------+-------+-------+

    - Relevant flags are only:
        -> TP-UDHI (User Data Header Indicator) on Bit 6
        -> TP-MTI (Message Type Indicator) on Bits 0-1, may be useful in the future.

    
    Second Octet (Byte 1)
    - TP-DCS
    - Defines the text/data format.
    
    0x00 -> GSM 7-bit (packed)
    0x04 -> 8-bit (UTF-8)
    0x08 -> UCS-2 (Unicode)


    Third Octet (Byte 2)
    - TP-UDL
    - Count of units in the entire TP-UD container (TP-UDHL, TP-UDH, Message Body).

    TP-UDHL:
    |-> A fixed 1 byte field

    TP-UDH:
    |-> Includes the size of all Information Elements (identifier, length, and actual data)

    Message Body:
    |-> When TP-DCS is 0x00, it is the # of characters, else when it is 
        0x04 or 0x08, it is the # of bytes/octets. The maximum length is
        140 bytes.


    Succeeding Octets (Bytes 3 to N)
    - TP-UD
    - Contains all message data.

    When TP-UDHI is 1, the following is prefixed:
    1. TP-UDHL (1 byte) - length of the TP-UDH
    2. TP-UDH (TP-UDHL bytes) - array of IEs
        - IEs are in the format:
         [IEI (1 byte)][IE-DL (1 byte)][IE-Data (N bytes)]
        |-> IEI - IE identifier
        |-> IE-DL - IE data length
        |-> IE-Data - actual IE data

        - *** SMS Concatenation:
        |-> TBD

        - *** SIGMA signature will be stored as an IE with the following parameters:
        |-> IEI: 0x80
        |-> IE-DL: size of signature
        |-> IE-Data: actual signature data
        
    (If TP-UDHI is 0, the above are omitted)

    It is the followed by:
    1. Message Body (TP-UDHL to N bytes) - the actual SMS message



    THINGS TO KEEP IN MIND:
    1. For GSM 7-bit encoding, TP-UDL is a septet (character) count, whereas
       the physical length of the buffer in memory is [(septets * 7) / 8] octets.
       For 8-bit binary and UCS-2 unicode, character count and byte length match.
*/

export enum SMSFlagsBitmask {
    MTI = 0x03, // TP-MTI
    UDHI = 0x40 // TP-UDHI
}

export enum SMSEncoding {
    GSM = 0x00, // 7-bit GSM
    UTF8 = 0x04, // 8-bit UTF8
    UNICODE = 0x08 // 16-bit Unicode
}

export interface SMSInformationElement {
    identifier: number, // IEI
    value: Uint8Array // IE-Data
}

export interface SMSPacket {
    encoding: SMSEncoding // TP-DCS
    elements: SMSInformationElement[] // TP-UDH (IEs)
    payload: Uint8Array; // TP-UD (Message Body)
}

export interface SMSBuildOptions {
    encoding: SMSEncoding
    elements: SMSInformationElement[]
}

export function build(payload: Uint8Array, options?: SMSBuildOptions): SMSPacket {
    // TODO: possible encoding detection and IE validation?
    const packet: SMSPacket = {
        encoding: options?.encoding ?? SMSEncoding.GSM,
        elements: options?.elements ?? [],
        payload
    }

    return packet
}

export function serialize(packet: SMSPacket): Uint8Array {
    const has_header = packet.elements.length > 0

    // Get size of TP-UDH (this is TP-UDHL)
    let header_size = packet.elements
        .map(e => e.value.length + 2)
        .reduce((a, b) => a + b)

    header_size += header_size ? 1 : 0

    // Get size of TP-UD (this is TP-UDL)
    let data_size = 0

    if (packet.encoding == SMSEncoding.GSM) {
        // GSM uses septets instead of octets
        const header = Math.ceil((header_size * 8) / 7)
        const body = Math.floor((packet.payload.length * 8) / 7)

        data_size = header + body
    } else {
        // UTF8 and Unicode uses octets
        data_size = header_size + packet.payload.length
    }

    let size = header_size + packet.payload.length
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
    const packet: SMSPacket = {
        encoding,
        elements,
        payload
    }

    return packet
}