export enum SMSEncoding {
    GSM = 0x00, // 7-bit GSM
    UTF8 = 0x04, // 8-bit UTF8
    UNICODE = 0x08 // 16-bit Unicode
}

// charsets
const GSM7_CHARSET = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ`¿abcdefghijklmnopqrstuvwxyzäöñüà";

// encoders and decoders
const encoder = new TextEncoder()
const utf8_decoder = new TextDecoder()
const unicode_decoder = new TextDecoder("utf-16be")

export function encode(text: string, encoding: SMSEncoding): Uint8Array {
    switch(encoding) {
        case SMSEncoding.GSM: {
            const byteLength = Math.ceil((text.length * 7) / 8);
            const bytes = new Uint8Array(byteLength);

            for (let i = 0; i < text.length; i++) {
                const idx = GSM7_CHARSET.indexOf(text[i]);
                const code = idx === -1 ? 0x3F : idx;

                const bitPos = i * 7;
                const byteIdx = Math.floor(bitPos / 8);
                const bitShift = bitPos % 8;

                // Place lower bits into current byte
                bytes[byteIdx] |= (code << bitShift) & 0xFF;

                // Spill overflow bits into the next byte if needed
                if (byteIdx + 1 < bytes.length) {
                    bytes[byteIdx + 1] |= (code >> (8 - bitShift)) & 0xFF;
                }
            }

            return bytes;
        }

        case SMSEncoding.UTF8:
            return encoder.encode(text)

        case SMSEncoding.UNICODE: {
            // 16-bit encoding implementation
            const bytes = new Uint8Array(text.length * 2);
            const view = new DataView(bytes.buffer);

            for (let i = 0; i < text.length; i++) {
                // false = Big-Endian
                view.setUint16(i * 2, text.charCodeAt(i), false);
            }
            
            return bytes;
        }
    }
}

export function decode(raw: Uint8Array, encoding: SMSEncoding): string {
    switch(encoding) {
        case SMSEncoding.GSM: {
            let result = "";
            const maxChars = Math.floor((raw.length * 8) / 7);

            for (let i = 0; i < maxChars; i++) {
                const bitPos = i * 7;
                const byteIdx = Math.floor(bitPos / 8);
                const bitShift = bitPos % 8;

                if (byteIdx >= raw.length) break;

                // Extract bits from current byte
                let code = raw[byteIdx] >> bitShift;
                const bitsFromFirst = 8 - bitShift;

                // Reconstruct overflow bits from the next byte if split across octets
                if (bitsFromFirst < 7 && byteIdx + 1 < raw.length) {
                    code |= raw[byteIdx + 1] << bitsFromFirst;
                }

                code &= 0x7F;

                // Stop if we encounter trailing padding zeros at the end
                if (code === 0 && i >= maxChars - 1 && raw[byteIdx] === 0) break;

                result += GSM7_CHARSET[code] || '';
            }

            return result;
        }   

        case SMSEncoding.UTF8:
            return utf8_decoder.decode(raw)

        case SMSEncoding.UNICODE:
            return unicode_decoder.decode(raw)
    }
}