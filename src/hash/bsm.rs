use crate::*;

use solana_nostd_sha256::hashv;
pub struct BSM;

const MAGIC_BYTES: &[u8] = b"\x18Bitcoin Signed Message:\n";

impl Secp256k1EcdsaHash for BSM {
    fn hash(message: &[u8]) -> [u8; 32] {
        let len = message.len();

        let mut buffer: [u8; 9] = [0u8; 9];
        let buffer_len = Self::encode_varint(len as u64, &mut buffer);

        hashv(&[&hashv(&[MAGIC_BYTES, &buffer[..buffer_len], message])])
    }
}

impl BSM {
    fn encode_varint(varint: u64, buffer: &mut [u8]) -> usize {
        if varint <= 252 {
            buffer[0] = varint as u8;
            1
        } else if varint <= 0xffff {
            buffer[0] = 0xfd;
            buffer[1] = (varint & 0xff) as u8;
            buffer[2] = ((varint >> 8) & 0xff) as u8;
            3
        } else if varint <= 0xffffffff {
            buffer[0] = 0xfe;
            buffer[1] = (varint & 0xff) as u8;
            buffer[2] = ((varint >> 8) & 0xff) as u8;
            buffer[3] = ((varint >> 16) & 0xff) as u8;
            buffer[4] = ((varint >> 24) & 0xff) as u8;
            5
        } else {
            buffer[0] = 0xff;
            buffer[1] = (varint & 0xff) as u8;
            buffer[2] = ((varint >> 8) & 0xff) as u8;
            buffer[3] = ((varint >> 16) & 0xff) as u8;
            buffer[4] = ((varint >> 24) & 0xff) as u8;
            buffer[5] = ((varint >> 32) & 0xff) as u8;
            buffer[6] = ((varint >> 40) & 0xff) as u8;
            buffer[7] = ((varint >> 48) & 0xff) as u8;
            buffer[8] = ((varint >> 56) & 0xff) as u8;
            9
        }
    }
}
