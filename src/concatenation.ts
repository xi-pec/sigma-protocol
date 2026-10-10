import { SMSInformationElement, SMSMessagePacket } from "./packet.js";

function ie(packet: SMSMessagePacket) {
    return packet.elements.find(e => e.identifier == 0x00 || e.identifier == 0x08)
}

export function split(packet: SMSMessagePacket): SMSMessagePacket[] {
    if (packet.elements.filter(e => e.identifier == 0x00 || e.identifier == 0x08).length) return [packet]

    let header_size = packet.elements.reduce((cur, next) => cur + next.value.length + 2, 0)
    if (header_size) header_size++
    if (packet.payload.length + header_size <= 140) return [packet]
    
    let filtered = packet.elements.filter(e => e.identifier == 0x43)
    let sigma = filtered.length ? filtered[0] : null
    let sigma_size = sigma ? 2 + sigma.value.length : 0

    // 140 - 1 (UDHL) - 5 (assume 8-bit concatenation) - 0 (no IE data yet) - sigma_size (1st part only)
    let parts_size = 134
    let extended = Math.ceil((packet.payload.length + sigma_size) / parts_size) > 255 ? true : false
    if (extended) parts_size--

    let initial = parts_size - sigma_size
    let parts_count = Math.ceil((packet.payload.length + sigma_size) / parts_size)

    let parts: SMSMessagePacket[] = []
    let ref = Math.floor(Math.random() * (extended ? 65536 : 256))

    let initial_elements: SMSInformationElement[] = [
        {
            identifier: extended ? 0x08 : 0x00,
            value: extended ? new Uint8Array([
                (ref >> 8) & 0xFF,
                ref & 0xFF,
                parts_count & 0xFF,
                0x01
            ]) : new Uint8Array([
                ref & 0xFF,
                parts_count & 0xFF,
                0x01
            ])
        }
    ]
    if (sigma) initial_elements.push(sigma)

    parts.push(new SMSMessagePacket(
        packet.payload.subarray(0, initial),
        {
            id: packet.id,
            encoding: packet.encoding,
            elements: initial_elements
        }
    ))

    for (let i = 0; i < parts_count - 1; i++) {
        let start = initial + parts_size * i
        let end = start + parts_size
        parts.push(new SMSMessagePacket(
            packet.payload.subarray(start, end),
            {
                id: packet.id,
                encoding: packet.encoding,
                elements: [{
                    identifier: extended ? 0x08 : 0x00,
                    value: extended ? new Uint8Array([
                        (ref >> 8) & 0xFF,
                        ref & 0xFF,
                        parts_count & 0xFF,
                        i + 2
                    ]) : new Uint8Array([
                        ref & 0xFF,
                        parts_count & 0xFF,
                        i + 2
                    ])
                }]
            }
        ))
    }

    return parts
}

export function concatenate(parts: SMSMessagePacket[]): SMSMessagePacket {
    if (parts.length == 0) 
        throw new Error("No parts to concatenate")

    let mapped: ({ ref: number, total: number, index: number, packet: SMSMessagePacket } | null)[] = parts.map(packet => {
        let data = ie(packet)
        if (!data) return null

        if (data.identifier == 0x00) {
            return {
                ref: data.value[0],
                total: data.value[1],
                index: data.value[2], 
                packet
            }
        } else {
            return {
                ref: data.value[0] * 256 + data.value[1],
                total: data.value[2],
                index: data.value[3], 
                packet
            }
        }
    })

    for (let data of mapped) {
        if (!mapped[0] || !data) 
            throw new Error("Malformed packets encountered")
        
        if (mapped[0].ref != data.ref)
            throw new Error("Mismatched packet reference numbers")

        if (mapped[0].total != data.total)
            throw new Error("Mismatched packet total values")

        if (mapped[0].packet.encoding != data.packet.encoding)
            throw new Error("Mismatched encodings")
    }

    if (mapped[0] && mapped[0].total !== mapped.length) 
        throw new Error("Mismatched expected number of packets")

    let sorted = mapped
        .filter(e => e != null)
        .sort((a, b) => a.index - b.index)

    let id = sorted[0].packet.id
    let encoding = sorted[0].packet.encoding

    // what the hell is this bro
    let signature = sorted
        .find(e => e.packet.elements.find(e => e.identifier == 0x43))
        ?.packet.elements.find(e => e.identifier == 0x43)
        ?.value

    let size = sorted.reduce((cur, value) => cur + value.packet.payload.length, 0)
    let payload = new Uint8Array(size)

    let offset = 0
    for (const part of sorted) {
        payload.set(part.packet.payload, offset)
        offset += part.packet.payload.length
    }

    let packet = new SMSMessagePacket(payload, {
        id, encoding,
        elements: signature ? [{
            identifier: 0x43,
            value: signature
        }] : []
    })

    return packet
}
