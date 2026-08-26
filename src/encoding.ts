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

export function encode(text: string, encoding: SMSEncoding) {
    switch(encoding) {
        case SMSEncoding.GSM: {
            // 7-bit encoding implementation
            let bits = "";
            for (let i = 0; i < text.length; i++) {
                const idx = GSM7_CHARSET.indexOf(text[i]);
                const code = idx === -1 ? 0x3F : idx;
                bits += code.toString(2).padStart(7, '0');
            }

            // Pad to complete 8-bit bytes if necessary
            while (bits.length % 8 !== 0) {
                bits += '0';
            }

            const bytes = new Uint8Array(bits.length / 8);
            for (let i = 0; i < bytes.length; i++) {
                bytes[i] = parseInt(bits.slice(i * 8, (i + 1) * 8), 2);
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

export function decode(raw: Uint8Array, encoding: SMSEncoding) {
    switch(encoding) {
        case SMSEncoding.GSM: {
            // 7-bit decoding implementation
            let bits = "";
            for (let i = 0; i < raw.length; i++) {
                bits += raw[i].toString(2).padStart(8, '0');
            }

            let result = "";
            for (let i = 0; i + 7 <= bits.length; i += 7) {
                const septet = bits.slice(i, i + 7);
                const code = parseInt(septet, 2);

                // Stop if padding or invalid null terminator in certain contexts
                if (code === 0 && i + 7 > bits.length) break;
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