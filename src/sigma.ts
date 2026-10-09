import { SMSPacket } from "./packet.js";
import { p256 } from "@noble/curves/nist.js"
import { ed25519 } from "@noble/curves/ed25519.js";

export enum SignatureAlgorithm {
  ECDSA = 0x00,
  ED25519 = 0x01,
}

export type KeyKind = "shared" | "secret";

export class SignatureAlgorithmKey<
  A extends SignatureAlgorithm = SignatureAlgorithm,
  K extends KeyKind = KeyKind,
> {
  readonly key: Uint8Array;
  readonly algorithm: A;
  readonly kind: K;

  constructor(key: Uint8Array, algorithm: A, kind: K) {
    this.key = key;
    this.algorithm = algorithm;
    this.kind = kind;
  }
}

export class SignatureAlgorithmSharedKey<
  A extends SignatureAlgorithm = SignatureAlgorithm,
> extends SignatureAlgorithmKey<A, "shared"> {
  constructor(key: Uint8Array, algorithm: A) {
    super(key, algorithm, "shared");
  }
}

export class SignatureAlgorithmSecretKey<
  A extends SignatureAlgorithm = SignatureAlgorithm,
> extends SignatureAlgorithmKey<A, "secret"> {
  constructor(key: Uint8Array, algorithm: A) {
    super(key, algorithm, "secret");
  }
}

export function keygen<A extends SignatureAlgorithm>(algorithm: A): { 
    shared: SignatureAlgorithmKey<A>,
    secret: SignatureAlgorithmKey<A>
} {
    const selected = {
        0x00: p256,
        0x01: ed25519
    }[algorithm]

    const keys = selected.keygen()

    return {
        shared: new SignatureAlgorithmSharedKey(keys.publicKey, algorithm),
        secret: new SignatureAlgorithmSharedKey(keys.secretKey, algorithm)
    }
}

export function sign<A extends SignatureAlgorithm>(packet: SMSPacket, algorithm: A, secret: SignatureAlgorithmSecretKey<A>): SMSPacket {
    if (packet.elements.find(e => e.identifier == 0x43)) return packet

    const selected = {
        0x00: p256,
        0x01: ed25519
    }[algorithm]

    const signature = selected.sign(packet.payload, secret.key)

    const data = new Uint8Array(1 + signature.length)
    data[0] = algorithm
    data.set(signature, 1)

    packet.elements.push({
        identifier: 0x43,
        value: data
    })

    return packet
}

export function verify<A extends SignatureAlgorithm>(packet: SMSPacket, shared: SignatureAlgorithmSharedKey<A>): boolean {
    const element = packet.elements.find(e => e.identifier == 0x43)
    if (!element) return false

    const algorithm = element.value[0]
    const signature = element.value.subarray(1)

    if (algorithm != shared.algorithm) return false

    const selected = {
        0x00: p256,
        0x01: ed25519
    }[algorithm]

    if (!selected) return false

    return selected.verify(signature, packet.payload, shared.key)
}