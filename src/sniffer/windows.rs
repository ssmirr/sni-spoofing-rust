use std::io;
use std::net::SocketAddr;

use tracing::info;
use windivert::prelude::*;

use super::RawBackend;
use crate::error::SnifferError;

pub struct WinDivertBackend {
    handle: WinDivert<NetworkLayer>,
}

impl WinDivertBackend {
    pub fn open(upstreams: &[SocketAddr]) -> Result<Self, SnifferError> {
        let mut parts = Vec::new();
        for addr in upstreams {
            let ip = addr.ip();
            let port = addr.port();
            match ip {
                std::net::IpAddr::V4(v4) => {
                    parts.push(format!(
                        "(ip.SrcAddr == {0} and tcp.SrcPort == {1}) or (ip.DstAddr == {0} and tcp.DstPort == {1})",
                        v4, port
                    ));
                }
                std::net::IpAddr::V6(v6) => {
                    parts.push(format!(
                        "(ipv6.SrcAddr == {0} and tcp.SrcPort == {1}) or (ipv6.DstAddr == {0} and tcp.DstPort == {1})",
                        v6, port
                    ));
                }
            }
        }
        let filter_str = format!("tcp and ({})", parts.join(" or "));
        info!(filter = %filter_str, "opening WinDivert handle");

        let handle = WinDivert::network(
            filter_str,
            0i16,
            WinDivertFlags::default(),
        ).map_err(|e| SnifferError::SocketOpen(io::Error::new(io::ErrorKind::Other, e.to_string())))?;

        info!("WinDivert handle opened");
        Ok(WinDivertBackend { handle })
    }
}

impl RawBackend for WinDivertBackend {
    fn frame_kind(&self) -> crate::packet::FrameKind { crate::packet::FrameKind::RawIp }

    fn skip_checksum_on_send(&self) -> bool { false }

    fn recv_frame(&mut self, buf: &mut [u8]) -> Result<usize, SnifferError> {
        let packet = self.handle.recv()
            .map_err(|e| SnifferError::Recv(io::Error::new(io::ErrorKind::Other, e.to_string())))?;

        let data = &packet.data;
        let len = data.len().min(buf.len());
        buf[..len].copy_from_slice(&data[..len]);

        self.handle.send(&packet)
            .map_err(|e| SnifferError::Recv(io::Error::new(io::ErrorKind::Other, format!("re-inject: {}", e))))?;

        Ok(len)
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), SnifferError> {
        let mut packet = WinDivertPacket::<NetworkLayer>::new(frame.to_vec());
        packet.address.set_outbound(true);
        packet.recalculate_checksums(Default::default());
        self.handle.send(&packet)
            .map_err(|e| SnifferError::Inject(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
        Ok(())
    }
}
