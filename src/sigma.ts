import { SMSPacket } from "./packet.js";
import { p256 } from "@noble/curves/nist.js"
import { ed25519 } from "@noble/curves/ed25519.js";

export enum SignatureAlgorithm {
    ECDSA = 0x00,
    ED25519 = 0x01
}

export type SignatureAlgorithmKey = Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>

export function sign(packet: SMSPacket, algorithm: SignatureAlgorithm, secret: SignatureAlgorithmKey): SMSPacket {
    if (packet.elements.find(e => e.identifier == 0x43)) return packet

    const selected = {
        0x00: p256,
        0x01: ed25519
    }[algorithm]

    const signature = selected.sign(packet.payload, secret)

    const data = new Uint8Array(1 + signature.length)
    data[0] = algorithm
    data.set(signature, 1)

    packet.elements.push({
        identifier: 0x43,
        value: data
    })

    return packet
}

export function verify(packet: SMSPacket, shared: SignatureAlgorithmKey): boolean {
    const element = packet.elements.find(e => e.identifier == 0x43)
    if (!element) return false

    const algorithm = element.value[0]
    const signature = element.value.subarray(1)

    const selected = {
        0x00: p256,
        0x01: ed25519
    }[algorithm]

    if (!selected) return false

    return selected.verify(signature, packet.payload, shared)
}