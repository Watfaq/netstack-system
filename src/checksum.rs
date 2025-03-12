use byteorder::{ByteOrder, NetworkEndian};
use smoltcp::wire::{Ipv4Packet, TcpPacket};

/// copied from smoltcp
pub fn combine(checksums: &[u16]) -> u16 {
    let mut accum: u32 = 0;
    for &word in checksums {
        accum += word as u32;
    }
    propagate_carries(accum)
}

/// copied from smoltcp
pub fn data(mut data: &[u8]) -> u16 {
    let mut accum = 0;

    // For each 32-byte chunk...
    const CHUNK_SIZE: usize = 32;
    while data.len() >= CHUNK_SIZE {
        let mut d = &data[..CHUNK_SIZE];
        // ... take by 2 bytes and sum them.
        while d.len() >= 2 {
            accum += NetworkEndian::read_u16(d) as u32;
            d = &d[2..];
        }

        data = &data[CHUNK_SIZE..];
    }

    // Sum the rest that does not fit the last 32-byte chunk,
    // taking by 2 bytes.
    while data.len() >= 2 {
        accum += NetworkEndian::read_u16(data) as u32;
        data = &data[2..];
    }

    // Add the last remaining odd byte, if any.
    if let Some(&value) = data.first() {
        accum += (value as u32) << 8;
    }

    propagate_carries(accum)
}

/// copied from smoltcp
const fn propagate_carries(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    sum as u16
}

/// incremental update checksum
pub trait UpdateCsum {
    fn update_csum(&mut self, diff_old: &[u8], diff_new: &[u8]);
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> UpdateCsum for Ipv4Packet<T> {
    fn update_csum(&mut self, diff_old: &[u8], diff_new: &[u8]) {
        let old_header_csum = self.checksum();
        let new_csum = combine(&[!old_header_csum, !data(diff_old), data(diff_new)]);
        let new_header_csum = !new_csum;
        self.set_checksum(new_header_csum);
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> UpdateCsum for TcpPacket<T> {
    fn update_csum(&mut self, diff_old: &[u8], diff_new: &[u8]) {
        let old_header_csum = self.checksum();
        let new_csum = combine(&[!old_header_csum, !data(diff_old), data(diff_new)]);
        let new_header_csum = !new_csum;
        self.set_checksum(new_header_csum);
    }
}
