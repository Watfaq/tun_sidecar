#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::{__sk_buff, TC_ACT_PIPE},
    helpers::gen::bpf_redirect,
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
    EbpfContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use tun_sidecar_common::TUN_INDEX_KEY;

#[map]
static PARAMS: HashMap<u32, u32> = HashMap::with_max_entries(8, 0);

#[map]
static BYPASS_MARKS: HashMap<u32, u8> = HashMap::with_max_entries(128, 0);

#[inline(always)]
fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, i32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(TC_ACT_PIPE);
    }

    Ok((start + offset) as *const T)
}

#[classifier]
pub fn tun_sidecar(ctx: TcContext) -> i32 {
    match try_tun_sidecar(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

pub fn is_clash(ctx: &TcContext) -> bool {
    let ptr = ctx.as_ptr() as *mut __sk_buff;
    let ptr = unsafe { &*ptr };
    let mark = ptr.mark;
    if unsafe { BYPASS_MARKS.get(&mark) }.is_some() {
        return true;
    }

    false
}

fn try_tun_sidecar(ctx: TcContext) -> Result<i32, i32> {
    if is_clash(&ctx) {
        return Ok(TC_ACT_PIPE);
    }

    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let src = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dst = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let (sport, dport, proto) = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

            (
                u16::from_be(unsafe { (*tcphdr).source }),
                u16::from_be(unsafe { (*tcphdr).dest }),
                "tcp",
            )
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            (
                u16::from_be(unsafe { (*udphdr).source }),
                u16::from_be(unsafe { (*udphdr).dest }),
                "udp",
            )
        }
        _ => return Err(TC_ACT_PIPE),
    };

    if dst == 0x01010101 {
        info!(
            &ctx,
            "{}, {:i}:{} => {:i}:{}", proto, src, sport, dst, dport
        );
        let tun_index = unsafe { PARAMS.get(&TUN_INDEX_KEY) };
        match tun_index {
            Some(&index) => unsafe {
                return Ok(bpf_redirect(index, 0) as i32);
            },
            None => {
                info!(&ctx, "tun_index not found");
                return Err(TC_ACT_PIPE);
            }
        }
    }

    Ok(TC_ACT_PIPE)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
