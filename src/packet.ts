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
        |-> IEI: 0x43
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

import { v4 } from "uuid"

import { concatenate, split } from "./concatenation.js"
import { SMSEncoding, encode, decode } from "./encoding.js"
import { serialize, deserialize } from "./serialization.js"
import { sign, SignatureAlgorithm, SignatureAlgorithmSecretKey, SignatureAlgorithmSharedKey, verify } from "./sigma.js"

export enum SMSFlagsBitmask {
    MTI = 0x03, // TP-MTI
    UDHI = 0x40 // TP-UDHI
}

export enum SMSMessageTypeIndicator {
    SUBMIT = 0x01,
    STATUS_REPORT = 0x02,
    KEYSHARE = 0x03
}

export interface SMSInformationElement {
    identifier: number, // IEI
    value: Uint8Array // IE-Data
}

export interface SMSAcknowledgementPacketOptions {
    timestamp?: number
}

export interface SMSMessagePacketOptions {
    id?: string
    encoding?: SMSEncoding
    elements?: SMSInformationElement[]
}

export class SMSPacket {
  static deserialize(raw: Uint8Array): SMSAcknowledgementPacket | SMSMessagePacket | SMSKeyPacket | null {
    if (!raw || raw.length === 0) return null
    const mti = raw[0] & SMSFlagsBitmask.MTI;

    switch (mti) {
        case SMSMessageTypeIndicator.STATUS_REPORT:
            return SMSAcknowledgementPacket.deserialize(raw);

        case SMSMessageTypeIndicator.SUBMIT:
            return SMSMessagePacket.deserialize(raw);

        case SMSMessageTypeIndicator.KEYSHARE:
            return SMSKeyPacket.deserialize(raw);

        default:
            return null
    }
  }
}

export class SMSAcknowledgementPacket {
    id: string
    timestamp: number

    constructor(id: string, options?: SMSAcknowledgementPacketOptions) {
        this.id = id
        this.timestamp = options?.timestamp ?? Date.now()
    }

    static deserialize(raw: Uint8Array) {
        return deserialize(raw)
    }

    serialize() {
        return serialize(this)
    }
}

export class SMSMessagePacket {
    id: string // TP-MR
    encoding: SMSEncoding // TP-DCS
    elements: SMSInformationElement[] // TP-UDH (IEs)
    payload: Uint8Array; // TP-UD (Message Body)

    constructor(payload: string | Uint8Array, options?: SMSMessagePacketOptions) {
        this.id = v4()
        this.encoding = options?.encoding ?? SMSEncoding.GSM
        this.elements = options?.elements ?? []
        
        // Filter out invalid IE data
        this.elements = this.elements.filter(e => {
            switch(e.identifier) {
                case 0x00: // 8-bit concatenation
                case 0x08: // 16-bit concatenation
                case 0x43: // SIGMA singatures
                    return true
                
                default:
                    return false
            }
        })

        // Encode input if string payload is passed
        if (typeof payload === "string") {
            this.payload = encode(payload, this.encoding)
        } else {
            this.payload = payload
        }
    }

    static deserialize(raw: Uint8Array<ArrayBufferLike>) {
        return deserialize(raw)
    }

    static concatenate(parts: SMSMessagePacket[]) {
        return concatenate(parts)
    }

    serialize() {
        return serialize(this)
    }

    split() {
        return split(this)
    }

    sign<A extends SignatureAlgorithm>(algorithm: A, secret: SignatureAlgorithmSecretKey<A>) {
        return sign(this, algorithm, secret)
    }

    verify<A extends SignatureAlgorithm>(shared: SignatureAlgorithmSharedKey<A>) {
        return verify(this, shared)
    }

    decode() {
        return decode(this.payload, this.encoding)
    }
}

export class SMSKeyPacket {
    ecdsa: SignatureAlgorithmSharedKey<SignatureAlgorithm.ECDSA>
    ed25519: SignatureAlgorithmSharedKey<SignatureAlgorithm.ED25519>

    constructor(
        ecdsa: SignatureAlgorithmSharedKey<SignatureAlgorithm.ECDSA>,
        ed25519: SignatureAlgorithmSharedKey<SignatureAlgorithm.ED25519>
    ) {
        this.ecdsa = ecdsa
        this.ed25519 = ed25519
    }

    static deserialize(raw: Uint8Array) {
        return deserialize(raw)
    }

    serialize() {
        return serialize(this)
    }
}