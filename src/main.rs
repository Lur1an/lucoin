use hex_literal::hex;
use sha3::{digest::Output, Digest, Sha3_256};
use std::time::{SystemTime, UNIX_EPOCH};

fn timestamp_now_seconds() -> u64 {
    let current_system_time = SystemTime::now();
    let duration_since_epoch = current_system_time.duration_since(UNIX_EPOCH).unwrap();
    duration_since_epoch.as_secs()
}

#[derive(Debug)]
pub struct BlockHeader {
    pub content_hash: Output<Sha3_256>,
    pub prev_header_hash: Output<Sha3_256>,
    pub nonce: u32,
    pub timestamp: u64,
}

impl BlockHeader {
    pub fn hash(&self) -> Output<Sha3_256> {
        let mut hasher = Sha3_256::new();
        hasher.update(self.content_hash);
        hasher.update(self.prev_header_hash);
        hasher.finalize()
    }
}

#[derive(Debug)]
pub struct Block {
    pub header: BlockHeader,
    pub content: Vec<u8>,
}

impl Block {
    pub fn origin(content: impl AsRef<[u8]>) -> Self {
        let content_hash = {
            let mut hasher = Sha3_256::new();
            hasher.update(content.as_ref());
            hasher.finalize()
        };
        let header = BlockHeader {
            content_hash,
            prev_header_hash: Output::<Sha3_256>::default(),
            nonce: 0,
            timestamp: timestamp_now_seconds(),
        };
        Self {
            content: content.as_ref().to_vec(),
            header,
        }
    }

    pub fn mine(
        content: impl AsRef<[u8]>,
        prev_block_header: &BlockHeader,
        target_hash: &[u8; 32],
    ) -> Self {
        let content = content.as_ref();
        let content_hash = {
            let mut hasher = Sha3_256::new();
            hasher.update(content);
            hasher.finalize()
        };
        let prev_header_hash = prev_block_header.hash();
        loop {
            let timestamp = timestamp_now_seconds();
            let mut hasher = Sha3_256::new();
            hasher.update(content);
            hasher.update(prev_header_hash);
            for nonce in 0..=u32::MAX {
                let mut hasher = hasher.clone();
                hasher.update((nonce as u64 + timestamp).to_le_bytes());
                let hash = hasher.finalize();
                if hash.as_slice() < target_hash {
                    return Self {
                        header: BlockHeader {
                            content_hash,
                            prev_header_hash,
                            nonce,
                            timestamp,
                        },
                        content: content.as_ref().to_vec(),
                    };
                }
            }
        }
    }
}

fn main() {
    let origin = Block::origin(b"Deez");
    let target = hex!("00000990900000000003255b0000000000000000000000000000000000000000");
    let block = Block::mine("Hello Block!", &origin.header, &target);
    println!("{:?}", block);
}
