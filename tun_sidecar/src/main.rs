use aya::{
    maps::HashMap,
    programs::{tc, SchedClassifier, TcAttachType},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;
use tun_sidecar_common::TUN_INDEX_KEY;

#[derive(Debug, Parser)]
struct Opt {
    /// the interfaces to attach the tc eBPF program to
    #[clap(short, long)]
    ifaces: Vec<String>,
    // target tun interface to redirect the packets to
    #[clap(short, long)]
    tun_name: String,
    /// marks for bypassing the tc eBPF program
    #[clap(short = 'm', long)]
    bypass_marks: Vec<u32>,
    #[clap(short = 'p', long)]
    bypass_pids: Vec<u32>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::try_parse()?;

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/tun_sidecar"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let Opt {
        ifaces,
        tun_name,
        bypass_marks: marks,
        bypass_pids: pids,
    } = opt;
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    for iface in &ifaces {
        let _ = tc::qdisc_add_clsact(&iface);
        let program: &mut SchedClassifier = ebpf.program_mut("tun_sidecar").unwrap().try_into()?;
        program.load()?;
        program.attach(&iface, TcAttachType::Egress)?;
    }

    {
        let ifindex = ifindex_from_ifname(&tun_name)?;
        let mut params: HashMap<_, u32, u32> = HashMap::try_from(ebpf.map_mut("PARAMS").unwrap())?;
        params.insert(TUN_INDEX_KEY, ifindex, 0)?;
    }

    {
        let mut bypass_marks: HashMap<_, u32, u8> =
            HashMap::try_from(ebpf.map_mut("BYPASS_MARKS").unwrap())?;
        for mark in marks {
            bypass_marks.insert(mark, 0, 0)?;
        }
    }

    {
        let mut bypass_pids: HashMap<_, u32, u8> =
            HashMap::try_from(ebpf.map_mut("BYPASS_PIDS").unwrap())?;
        for pid in pids {
            bypass_pids.insert(pid, 0, 0)?;
        }
    }
    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

fn ifindex_from_ifname(if_name: &str) -> Result<u32, std::io::Error> {
    let c_str_if_name = std::ffi::CString::new(if_name)?;
    let c_if_name = c_str_if_name.as_ptr();
    // Safety: libc wrapper
    let if_index = unsafe { libc::if_nametoindex(c_if_name) };
    if if_index == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(if_index)
}
