// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate vmm;
extern crate vmm_sys_util;

#[macro_use(crate_version, crate_authors)]
extern crate clap;

use clap::{App, Arg, ArgGroup};
use libc::EFD_NONBLOCK;
use log::LevelFilter;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::{env, process};
use vmm::config;
use vmm_sys_util::eventfd::EventFd;

struct Logger {
    output: Mutex<Box<dyn std::io::Write + Send>>,
    start: std::time::Instant,
}

impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let now = std::time::Instant::now();
        let duration = now.duration_since(self.start);

        if record.file().is_some() && record.line().is_some() {
            writeln!(
                *(*(self.output.lock().unwrap())),
                "cloud-hypervisor: {:?}: {}:{}:{} -- {}",
                duration,
                record.level(),
                record.file().unwrap(),
                record.line().unwrap(),
                record.args()
            )
            .expect("Failed to write to log file");
        } else {
            writeln!(
                *(*(self.output.lock().unwrap())),
                "cloud-hypervisor: {:?}: {}:{} -- {}",
                duration,
                record.level(),
                record.target(),
                record.args()
            )
            .expect("Failed to write to log file");
        }
    }
    fn flush(&self) {}
}

fn main() {
    let pid = unsafe { libc::getpid() };
    let uid = unsafe { libc::getuid() };

    let mut api_server_path = format! {"/run/user/{}/cloud-hypervisor.{}", uid, pid};
    if uid == 0 {
        // If we're running as root, we try to get the real user ID if we've been sudo'ed
        // or else create our socket directly under /run.
        let key = "SUDO_UID";
        match env::var(key) {
            Ok(sudo_uid) => {
                api_server_path = format! {"/run/user/{}/cloud-hypervisor.{}", sudo_uid, pid}
            }
            Err(_) => api_server_path = format! {"/run/cloud-hypervisor.{}", pid},
        }
    }

    let default_vcpus = format! {"{}", config::DEFAULT_VCPUS};
    let default_memory = format! {"size={}M", config::DEFAULT_MEMORY_MB};
    let default_rng = format! {"src={}", config::DEFAULT_RNG_SOURCE};

    let cmd_arguments = App::new("cloud-hypervisor")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Launch a cloud-hypervisor VMM.")
        .group(ArgGroup::with_name("vm-config").multiple(true))
        .group(ArgGroup::with_name("vmm-config").multiple(true))
        .arg(
            Arg::with_name("cpus")
                .long("cpus")
                .help("Number of virtual CPUs")
                .default_value(&default_vcpus)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("memory")
                .long("memory")
                .help(
                    "Memory parameters \"size=<guest_memory_size>,\
                     file=<backing_file_path>\"",
                )
                .default_value(&default_memory)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("kernel")
                .long("kernel")
                .help("Path to kernel image (vmlinux)")
                .takes_value(true)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("cmdline")
                .long("cmdline")
                .help("Kernel command line")
                .takes_value(true)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("disk")
                .long("disk")
                .help(
                    "Disk parameters \"path=<disk_image_path>,\
                     iommu=on|off\"",
                )
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("net")
                .long("net")
                .help(
                    "Network parameters \"tap=<if_name>,\
                     ip=<ip_addr>,mask=<net_mask>,mac=<mac_addr>,\
                     iommu=on|off\"",
                )
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("rng")
                .long("rng")
                .help(
                    "Random number generator parameters \
                     \"src=<entropy_source_path>,iommu=on|off\"",
                )
                .default_value(&default_rng)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("fs")
                .long("fs")
                .help(
                    "virtio-fs parameters \"tag=<tag_name>,\
                     sock=<socket_path>,num_queues=<number_of_queues>,\
                     queue_size=<size_of_each_queue>,dax=on|off,\
                     cache_size=<DAX cache size: default 8Gib>\"",
                )
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("pmem")
                .long("pmem")
                .help(
                    "Persistent memory parameters \"file=<backing_file_path>,\
                     size=<persistent_memory_size>,iommu=on|off\"",
                )
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("serial")
                .long("serial")
                .help("Control serial port: off|null|tty|file=/path/to/a/file")
                .default_value("null")
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("console")
                .long("console")
                .help(
                    "Control (virtio) console: \"off|null|tty|file=/path/to/a/file,\
                     iommu=on|off\"",
                )
                .default_value("tty")
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("device")
                .long("device")
                .help("Direct device assignment parameter")
                .help(
                    "Direct device assignment parameters \
                     \"path=<device_path>,iommu=on|off\"",
                )
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("vhost-user-net")
                .long("vhost-user-net")
                .help(
                    "Network parameters \"mac=<mac_addr>,\
                     sock=<socket_path>, num_queues=<number_of_queues>,\
                     queue_size=<size_of_each_queue>\"",
                )
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("vsock")
                .long("vsock")
                .help(
                    "Virtio VSOCK parameters \"cid=<context_id>,\
                     sock=<socket_path>,iommu=on|off\"",
                )
                .takes_value(true)
                .min_values(1)
                .group("vm-config"),
        )
        .arg(
            Arg::with_name("vhost-user-blk")
                .long("vhost-user-blk")
                .help(
                    "Vhost user Block parameters \"sock=<socket_path>,\
                     num_queues=<number_of_queues>,\
                     queue_size=<size_of_each_queue>, \
                     wce=<true|false, default true>\"",
                )
                .takes_value(true)
                .min_values(1),
        )
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of debugging output")
                .group("vmm-config"),
        )
        .arg(
            Arg::with_name("log-file")
                .long("log-file")
                .help("Log file. Standard error is used if not specified")
                .takes_value(true)
                .min_values(1)
                .group("vmm-config"),
        )
        .arg(
            Arg::with_name("api-socket")
                .long("api-socket")
                .help("HTTP API socket path (UNIX domain socket).")
                .takes_value(true)
                .min_values(1)
                .default_value(&api_server_path)
                .group("vmm-config"),
        )
        .get_matches();

    // These .unwrap()s cannot fail as there is a default value defined
    let cpus = cmd_arguments.value_of("cpus").unwrap();
    let memory = cmd_arguments.value_of("memory").unwrap();
    let rng = cmd_arguments.value_of("rng").unwrap();
    let serial = cmd_arguments.value_of("serial").unwrap();

    let kernel = cmd_arguments.value_of("kernel");
    let cmdline = cmd_arguments.value_of("cmdline");

    let disks: Option<Vec<&str>> = cmd_arguments.values_of("disk").map(|x| x.collect());
    let net: Option<Vec<&str>> = cmd_arguments.values_of("net").map(|x| x.collect());
    let console = cmd_arguments.value_of("console").unwrap();
    let fs: Option<Vec<&str>> = cmd_arguments.values_of("fs").map(|x| x.collect());
    let pmem: Option<Vec<&str>> = cmd_arguments.values_of("pmem").map(|x| x.collect());
    let devices: Option<Vec<&str>> = cmd_arguments.values_of("device").map(|x| x.collect());
    let vhost_user_net: Option<Vec<&str>> = cmd_arguments
        .values_of("vhost-user-net")
        .map(|x| x.collect());
    let vhost_user_blk: Option<Vec<&str>> = cmd_arguments
        .values_of("vhost-user-blk")
        .map(|x| x.collect());
    let vsock: Option<Vec<&str>> = cmd_arguments.values_of("vsock").map(|x| x.collect());

    let log_level = match cmd_arguments.occurrences_of("v") {
        0 => LevelFilter::Error,
        1 => LevelFilter::Warn,
        2 => LevelFilter::Info,
        3 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    let log_file: Box<dyn std::io::Write + Send> =
        if let Some(file) = cmd_arguments.value_of("log-file") {
            Box::new(
                std::fs::File::create(std::path::Path::new(file)).expect("Error creating log file"),
            )
        } else {
            Box::new(std::io::stderr())
        };

    log::set_boxed_logger(Box::new(Logger {
        output: Mutex::new(log_file),
        start: std::time::Instant::now(),
    }))
    .map(|()| log::set_max_level(log_level))
    .expect("Expected to be able to setup logger");

    let vm_config = match config::VmConfig::parse(config::VmParams {
        cpus,
        memory,
        kernel,
        cmdline,
        disks,
        net,
        rng,
        fs,
        pmem,
        serial,
        console,
        devices,
        vhost_user_net,
        vhost_user_blk,
        vsock,
    }) {
        Ok(config) => config,
        Err(e) => {
            println!("Failed parsing parameters {:?}", e);
            process::exit(1);
        }
    };

    let api_socket_path = cmd_arguments
        .value_of("api-socket")
        .expect("Missing argument: api-socket");

    println!(
        "Cloud Hypervisor Guest\n\tAPI server: {}\n\tvCPUs: {}\n\tMemory: {} MB\
         \n\tKernel: {:?}\n\tKernel cmdline: {}\n\tDisk(s): {:?}",
        api_socket_path,
        vm_config.cpus.cpu_count,
        vm_config.memory.size >> 20,
        vm_config.kernel,
        vm_config.cmdline.args.as_str(),
        vm_config.disks,
    );

    let (api_request_sender, api_request_receiver) = channel();
    let api_evt = EventFd::new(EFD_NONBLOCK).expect("Cannot create API EventFd");

    let http_sender = api_request_sender.clone();
    let vmm_thread = match vmm::start_vmm_thread(
        api_socket_path,
        api_evt.try_clone().unwrap(),
        http_sender,
        api_request_receiver,
    ) {
        Ok(t) => t,
        Err(e) => {
            println!("Failed spawning the VMM thread {:?}", e);
            process::exit(1);
        }
    };

    if cmd_arguments.is_present("vm-config") && vm_config.valid() {
        // Create and boot the VM based off the VM config we just built.
        let sender = api_request_sender.clone();
        vmm::api::vm_create(
            api_evt.try_clone().unwrap(),
            api_request_sender,
            Arc::new(vm_config),
        )
        .expect("Could not create the VM");
        vmm::api::vm_boot(api_evt.try_clone().unwrap(), sender).expect("Could not boot the VM");
    }

    match vmm_thread.join() {
        Ok(res) => match res {
            Ok(_) => (),
            Err(e) => {
                println!("VMM thread failed {:?}", e);
                process::exit(1);
            }
        },
        Err(e) => {
            println!("Could not joing VMM thread {:?}", e);
            process::exit(1);
        }
    }
}

#[cfg(test)]
#[cfg(feature = "integration_tests")]
#[macro_use]
extern crate credibility;

#[cfg(test)]
#[cfg(feature = "integration_tests")]
#[macro_use]
extern crate lazy_static;

#[cfg(test)]
#[cfg(feature = "integration_tests")]
mod tests {
    #![allow(dead_code)]
    use ssh2::Session;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::process::{Command, Stdio};
    use std::string::String;
    use std::sync::Mutex;
    use std::thread;
    use tempdir::TempDir;

    lazy_static! {
        static ref NEXT_VM_ID: Mutex<u8> = Mutex::new(1);
    }

    struct GuestNetworkConfig {
        guest_ip: String,
        l2_guest_ip: String,
        host_ip: String,
        guest_mac: String,
        l2_guest_mac: String,
    }

    struct Guest<'a> {
        tmp_dir: TempDir,
        disk_config: &'a dyn DiskConfig,
        fw_path: String,
        network: GuestNetworkConfig,
    }

    // Safe to implement as we know we have no interior mutability
    impl<'a> std::panic::RefUnwindSafe for Guest<'a> {}

    enum DiskType {
        OperatingSystem,
        RawOperatingSystem,
        CloudInit,
    }

    trait DiskConfig {
        fn prepare_files(&mut self, tmp_dir: &TempDir, network: &GuestNetworkConfig);
        fn prepare_cloudinit(&self, tmp_dir: &TempDir, network: &GuestNetworkConfig) -> String;
        fn disk(&self, disk_type: DiskType) -> Option<String>;
    }

    struct ClearDiskConfig {
        osdisk_path: String,
        osdisk_raw_path: String,
        cloudinit_path: String,
    }

    impl ClearDiskConfig {
        fn new() -> Self {
            ClearDiskConfig {
                osdisk_path: String::new(),
                osdisk_raw_path: String::new(),
                cloudinit_path: String::new(),
            }
        }
    }

    struct UbuntuDiskConfig {
        osdisk_raw_path: String,
        cloudinit_path: String,
        image_name: String,
    }

    const BIONIC_IMAGE_NAME: &str = "bionic-server-cloudimg-amd64-raw.img";
    const EOAN_IMAGE_NAME: &str = "eoan-server-cloudimg-amd64-raw.img";

    impl UbuntuDiskConfig {
        fn new(image_name: String) -> Self {
            UbuntuDiskConfig {
                image_name,
                osdisk_raw_path: String::new(),
                cloudinit_path: String::new(),
            }
        }
    }

    impl DiskConfig for ClearDiskConfig {
        fn prepare_cloudinit(&self, tmp_dir: &TempDir, network: &GuestNetworkConfig) -> String {
            let cloudinit_file_path =
                String::from(tmp_dir.path().join("cloudinit").to_str().unwrap());

            let cloud_init_directory = tmp_dir
                .path()
                .join("cloud-init")
                .join("clear")
                .join("openstack");

            fs::create_dir_all(&cloud_init_directory.join("latest"))
                .expect("Expect creating cloud-init directory to succeed");

            let source_file_dir = std::env::current_dir()
                .unwrap()
                .join("test_data")
                .join("cloud-init")
                .join("clear")
                .join("openstack")
                .join("latest");

            fs::copy(
                source_file_dir.join("meta_data.json"),
                cloud_init_directory.join("latest").join("meta_data.json"),
            )
            .expect("Expect copying cloud-init meta_data.json to succeed");

            let mut user_data_string = String::new();

            fs::File::open(source_file_dir.join("user_data"))
                .unwrap()
                .read_to_string(&mut user_data_string)
                .expect("Expected reading user_data file in to succeed");

            user_data_string = user_data_string.replace("192.168.2.1", &network.host_ip);
            user_data_string = user_data_string.replace("192.168.2.2", &network.guest_ip);
            user_data_string = user_data_string.replace("192.168.2.3", &network.l2_guest_ip);
            user_data_string = user_data_string.replace("12:34:56:78:90:ab", &network.guest_mac);
            user_data_string = user_data_string.replace("de:ad:be:ef:12:34", &network.l2_guest_mac);

            fs::File::create(cloud_init_directory.join("latest").join("user_data"))
                .unwrap()
                .write_all(&user_data_string.as_bytes())
                .expect("Expected writing out user_data to succeed");

            std::process::Command::new("mkdosfs")
                .args(&["-n", "config-2"])
                .args(&["-C", cloudinit_file_path.as_str()])
                .arg("8192")
                .output()
                .expect("Expect creating disk image to succeed");

            std::process::Command::new("mcopy")
                .arg("-o")
                .args(&["-i", cloudinit_file_path.as_str()])
                .args(&["-s", cloud_init_directory.to_str().unwrap(), "::"])
                .output()
                .expect("Expect copying files to disk image to succeed");

            cloudinit_file_path
        }

        fn prepare_files(&mut self, tmp_dir: &TempDir, network: &GuestNetworkConfig) {
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut osdisk_base_path = workload_path.clone();
            osdisk_base_path.push("clear-31310-cloudguest.img");

            let mut osdisk_raw_base_path = workload_path.clone();
            osdisk_raw_base_path.push("clear-31310-cloudguest-raw.img");

            let osdisk_path = String::from(tmp_dir.path().join("osdisk.img").to_str().unwrap());
            let osdisk_raw_path =
                String::from(tmp_dir.path().join("osdisk_raw.img").to_str().unwrap());
            let cloudinit_path = self.prepare_cloudinit(tmp_dir, network);

            fs::copy(osdisk_base_path, &osdisk_path)
                .expect("copying of OS source disk image failed");
            fs::copy(osdisk_raw_base_path, &osdisk_raw_path)
                .expect("copying of OS source disk raw image failed");

            self.cloudinit_path = cloudinit_path;
            self.osdisk_path = osdisk_path;
            self.osdisk_raw_path = osdisk_raw_path;
        }

        fn disk(&self, disk_type: DiskType) -> Option<String> {
            match disk_type {
                DiskType::OperatingSystem => Some(self.osdisk_path.clone()),
                DiskType::RawOperatingSystem => Some(self.osdisk_raw_path.clone()),
                DiskType::CloudInit => Some(self.cloudinit_path.clone()),
            }
        }
    }

    impl DiskConfig for UbuntuDiskConfig {
        fn prepare_cloudinit(&self, tmp_dir: &TempDir, network: &GuestNetworkConfig) -> String {
            let cloudinit_file_path =
                String::from(tmp_dir.path().join("cloudinit").to_str().unwrap());

            let cloud_init_directory = tmp_dir.path().join("cloud-init").join("ubuntu");

            fs::create_dir_all(&cloud_init_directory)
                .expect("Expect creating cloud-init directory to succeed");

            let source_file_dir = std::env::current_dir()
                .unwrap()
                .join("test_data")
                .join("cloud-init")
                .join("ubuntu");

            vec!["meta-data", "user-data"].iter().for_each(|x| {
                fs::copy(source_file_dir.join(x), cloud_init_directory.join(x))
                    .expect("Expect copying cloud-init meta-data to succeed");
            });

            let mut network_config_string = String::new();

            fs::File::open(source_file_dir.join("network-config"))
                .unwrap()
                .read_to_string(&mut network_config_string)
                .expect("Expected reading network-config file in to succeed");

            network_config_string = network_config_string.replace("192.168.2.1", &network.host_ip);
            network_config_string = network_config_string.replace("192.168.2.2", &network.guest_ip);
            network_config_string =
                network_config_string.replace("12:34:56:78:90:ab", &network.guest_mac);

            fs::File::create(cloud_init_directory.join("network-config"))
                .unwrap()
                .write_all(&network_config_string.as_bytes())
                .expect("Expected writing out network-config to succeed");

            std::process::Command::new("mkdosfs")
                .args(&["-n", "cidata"])
                .args(&["-C", cloudinit_file_path.as_str()])
                .arg("8192")
                .output()
                .expect("Expect creating disk image to succeed");

            vec!["user-data", "meta-data", "network-config"]
                .iter()
                .for_each(|x| {
                    std::process::Command::new("mcopy")
                        .arg("-o")
                        .args(&["-i", cloudinit_file_path.as_str()])
                        .args(&["-s", cloud_init_directory.join(x).to_str().unwrap(), "::"])
                        .output()
                        .expect("Expect copying files to disk image to succeed");
                });

            cloudinit_file_path
        }

        fn prepare_files(&mut self, tmp_dir: &TempDir, network: &GuestNetworkConfig) {
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut osdisk_raw_base_path = workload_path.clone();
            osdisk_raw_base_path.push(&self.image_name);

            let osdisk_raw_path =
                String::from(tmp_dir.path().join("osdisk_raw.img").to_str().unwrap());
            let cloudinit_path = self.prepare_cloudinit(tmp_dir, network);

            fs::copy(osdisk_raw_base_path, &osdisk_raw_path)
                .expect("copying of OS source disk raw image failed");

            self.cloudinit_path = cloudinit_path;
            self.osdisk_raw_path = osdisk_raw_path;
        }

        fn disk(&self, disk_type: DiskType) -> Option<String> {
            match disk_type {
                DiskType::OperatingSystem | DiskType::RawOperatingSystem => {
                    Some(self.osdisk_raw_path.clone())
                }
                DiskType::CloudInit => Some(self.cloudinit_path.clone()),
            }
        }
    }

    fn prepare_virtiofsd(
        tmp_dir: &TempDir,
        shared_dir: &str,
        cache: &str,
    ) -> (std::process::Child, String) {
        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let mut virtiofsd_path = workload_path.clone();
        virtiofsd_path.push("virtiofsd");
        let virtiofsd_path = String::from(virtiofsd_path.to_str().unwrap());

        let virtiofsd_socket_path =
            String::from(tmp_dir.path().join("virtiofs.sock").to_str().unwrap());

        // Start the daemon
        let child = Command::new(virtiofsd_path.as_str())
            .args(&[
                "-o",
                format!("vhost_user_socket={}", virtiofsd_socket_path).as_str(),
            ])
            .args(&["-o", format!("source={}", shared_dir).as_str()])
            .args(&["-o", format!("cache={}", cache).as_str()])
            .spawn()
            .unwrap();

        thread::sleep(std::time::Duration::new(10, 0));

        (child, virtiofsd_socket_path)
    }

    fn prepare_vubd(tmp_dir: &TempDir, blk_img: &str) -> (std::process::Child, String) {
        let mut workload_path = dirs::home_dir().unwrap();
        workload_path.push("workloads");

        let mut vubd_path = workload_path.clone();
        vubd_path.push("vubd");
        let vubd_path = String::from(vubd_path.to_str().unwrap());

        let mut blk_file_path = workload_path.clone();
        blk_file_path.push(blk_img);
        let blk_file_path = String::from(blk_file_path.to_str().unwrap());

        let vubd_socket_path = String::from(tmp_dir.path().join("vub.sock").to_str().unwrap());

        // Start the daemon
        let child = Command::new(vubd_path.as_str())
            .args(&["-b", blk_file_path.as_str()])
            .args(&["-s", vubd_socket_path.as_str()])
            .spawn()
            .unwrap();

        thread::sleep(std::time::Duration::new(10, 0));

        (child, vubd_socket_path)
    }

    fn temp_vsock_path(tmp_dir: &TempDir) -> String {
        String::from(tmp_dir.path().join("vsock").to_str().unwrap())
    }

    fn temp_api_path(tmp_dir: &TempDir) -> String {
        String::from(
            tmp_dir
                .path()
                .join("cloud-hypervisor.sock")
                .to_str()
                .unwrap(),
        )
    }

    fn curl_command(api_socket: &str, method: &str, url: &str, http_body: Option<&str>) {
        let mut curl_args: Vec<&str> =
            ["--unix-socket", api_socket, "-i", "-X", method, url].to_vec();

        println!("running curl");
        if let Some(body) = http_body {
            curl_args.push("-H");
            curl_args.push("Accept: application/json");
            curl_args.push("-H");
            curl_args.push("Content-Type: application/json");
            curl_args.push("-d");
            curl_args.push(body);
            println!("{}", body);
        }

        println!("{}", url);
        let status = Command::new("curl")
            .args(curl_args)
            .status()
            .expect("Failed to launch curl command");

        println!("curl done");
        assert!(status.success());
    }

    const DEFAULT_SSH_RETRIES: u8 = 6;
    const DEFAULT_SSH_TIMEOUT: u8 = 10;
    fn ssh_command_ip(command: &str, ip: &str, retries: u8, timeout: u8) -> Result<String, Error> {
        let mut s = String::new();

        let mut counter = 0;
        loop {
            match (|| -> Result<(), Error> {
                let tcp =
                    TcpStream::connect(format!("{}:22", ip)).map_err(|_| Error::Connection)?;
                let mut sess = Session::new().unwrap();
                sess.set_tcp_stream(tcp);
                sess.handshake().map_err(|_| Error::Connection)?;

                sess.userauth_password("cloud", "cloud123")
                    .map_err(|_| Error::Authentication)?;
                assert!(sess.authenticated());

                let mut channel = sess.channel_session().map_err(|_| Error::Command)?;
                channel.exec(command).map_err(|_| Error::Command)?;

                // Intentionally ignore these results here as their failure
                // does not precipitate a repeat
                let _ = channel.read_to_string(&mut s);
                let _ = channel.close();
                let _ = channel.wait_close();
                Ok(())
            })() {
                Ok(_) => break,
                Err(e) => {
                    counter += 1;
                    if counter >= retries {
                        return Err(e);
                    }
                }
            };
            thread::sleep(std::time::Duration::new((timeout * counter).into(), 0));
        }
        Ok(s)
    }

    #[derive(Debug)]
    enum Error {
        Connection,
        Authentication,
        Command,
        Parsing,
    }

    impl std::error::Error for Error {}

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self)
        }
    }

    impl<'a> Guest<'a> {
        fn new_from_ip_range(disk_config: &'a mut dyn DiskConfig, class: &str, id: u8) -> Self {
            let tmp_dir = TempDir::new("ch").unwrap();

            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let mut fw_path = workload_path.clone();
            fw_path.push("hypervisor-fw");
            let fw_path = String::from(fw_path.to_str().unwrap());
            let network = GuestNetworkConfig {
                guest_ip: format!("{}.{}.2", class, id),
                l2_guest_ip: format!("{}.{}.3", class, id),
                host_ip: format!("{}.{}.1", class, id),
                guest_mac: format!("12:34:56:78:90:{:02x}", id),
                l2_guest_mac: format!("de:ad:be:ef:12:{:02x}", id),
            };

            disk_config.prepare_files(&tmp_dir, &network);

            Guest {
                tmp_dir,
                disk_config,
                fw_path,
                network,
            }
        }

        fn new(disk_config: &'a mut dyn DiskConfig) -> Self {
            let mut guard = NEXT_VM_ID.lock().unwrap();
            let id = *guard;
            *guard = id + 1;

            Self::new_from_ip_range(disk_config, "192.168", id)
        }

        fn default_net_string(&self) -> String {
            format!(
                "tap=,mac={},ip={},mask=255.255.255.0",
                self.network.guest_mac, self.network.host_ip
            )
        }

        fn default_net_string_w_iommu(&self) -> String {
            format!(
                "tap=,mac={},ip={},mask=255.255.255.0,iommu=on",
                self.network.guest_mac, self.network.host_ip
            )
        }

        fn ssh_command(&self, command: &str) -> Result<String, Error> {
            println!("ssh {} '{}'", self.network.l2_guest_ip, command);
            ssh_command_ip(
                command,
                &self.network.guest_ip,
                DEFAULT_SSH_RETRIES,
                DEFAULT_SSH_TIMEOUT,
            )
        }

        fn ssh_command_l1(&self, command: &str) -> Result<String, Error> {
            ssh_command_ip(
                command,
                &self.network.guest_ip,
                DEFAULT_SSH_RETRIES,
                DEFAULT_SSH_TIMEOUT,
            )
        }

        fn ssh_command_l2(&self, command: &str) -> Result<String, Error> {
            ssh_command_ip(
                command,
                &self.network.l2_guest_ip,
                DEFAULT_SSH_RETRIES,
                DEFAULT_SSH_TIMEOUT,
            )
        }

        fn api_create_body(&self, cpu_count: u8) -> String {
            format! {"{{\"cpus\":{{\"cpu_count\":{}}},\"kernel\":{{\"path\":\"{}\"}},\"cmdline\":{{\"args\": \"\"}},\"net\":[{{\"ip\":\"{}\", \"mask\":\"255.255.255.0\", \"mac\":\"{}\"}}], \"disks\":[{{\"path\":\"{}\"}}, {{\"path\":\"{}\"}}]}}",
                     cpu_count,
                     self.fw_path.as_str(),
                     self.network.host_ip,
                     self.network.guest_mac,
                     self.disk_config.disk(DiskType::OperatingSystem).unwrap().as_str(),
                     self.disk_config.disk(DiskType::CloudInit).unwrap().as_str(),
            }
        }

        fn get_cpu_count(&self) -> Result<u32, Error> {
            Ok(self
                .ssh_command("grep -c processor /proc/cpuinfo")?
                .trim()
                .parse()
                .map_err(|_| Error::Parsing)?)
        }

        fn get_initial_apicid(&self) -> Result<u32, Error> {
            Ok(self
                .ssh_command("grep \"initial apicid\" /proc/cpuinfo | grep -o \"[0-9]*\"")?
                .trim()
                .parse()
                .map_err(|_| Error::Parsing)?)
        }

        fn get_total_memory(&self) -> Result<u32, Error> {
            Ok(self
                .ssh_command("grep MemTotal /proc/meminfo | grep -o \"[0-9]*\"")?
                .trim()
                .parse()
                .map_err(|_| Error::Parsing)?)
        }

        fn get_entropy(&self) -> Result<u32, Error> {
            Ok(self
                .ssh_command("cat /proc/sys/kernel/random/entropy_avail")?
                .trim()
                .parse()
                .map_err(|_| Error::Parsing)?)
        }

        fn get_pci_bridge_class(&self) -> Result<String, Error> {
            Ok(self
                .ssh_command("cat /sys/bus/pci/devices/0000:00:00.0/class")?
                .trim()
                .to_string())
        }

        fn get_pci_device_ids(&self) -> Result<String, Error> {
            Ok(self
                .ssh_command("cat /sys/bus/pci/devices/*/device")?
                .trim()
                .to_string())
        }

        fn get_pci_vendor_ids(&self) -> Result<String, Error> {
            Ok(self
                .ssh_command("cat /sys/bus/pci/devices/*/vendor")?
                .trim()
                .to_string())
        }

        fn does_device_vendor_pair_match(
            &self,
            device_id: &str,
            vendor_id: &str,
        ) -> Result<bool, Error> {
            // We are checking if console device's device id and vendor id pair matches
            let devices = self.get_pci_device_ids()?;
            let devices: Vec<&str> = devices.split('\n').collect();
            let vendors = self.get_pci_vendor_ids()?;
            let vendors: Vec<&str> = vendors.split('\n').collect();

            for (index, d_id) in devices.iter().enumerate() {
                if *d_id == device_id {
                    if let Some(v_id) = vendors.get(index) {
                        if *v_id == vendor_id {
                            return Ok(true);
                        }
                    }
                }
            }

            Ok(false)
        }

        fn valid_virtio_fs_cache_size(
            &self,
            dax: bool,
            cache_size: Option<u64>,
        ) -> Result<bool, Error> {
            let shm_region = self
                .ssh_command("sudo -E bash -c 'cat /proc/iomem' | grep virtio-pci-shm")?
                .trim()
                .to_string();

            if shm_region.is_empty() {
                return Ok(!dax);
            }

            // From this point, the region is not empty, hence it is an error
            // if DAX is off.
            if !dax {
                return Ok(false);
            }

            let cache = if let Some(cache) = cache_size {
                cache
            } else {
                // 8Gib by default
                0x0002_0000_0000
            };

            let args: Vec<&str> = shm_region.split(':').collect();
            if args.is_empty() {
                return Ok(false);
            }

            let args: Vec<&str> = args[0].trim().split('-').collect();
            if args.len() != 2 {
                return Ok(false);
            }

            let start_addr = u64::from_str_radix(args[0], 16).map_err(|_| Error::Parsing)?;
            let end_addr = u64::from_str_radix(args[1], 16).map_err(|_| Error::Parsing)?;

            Ok(cache == (end_addr - start_addr + 1))
        }
    }

    #[cfg_attr(not(feature = "mmio"), test)]
    // Start cloud-hypervisor with no VM parameters, only the API server running.
    // From the API: Create a VM, boot it and check that it looks as expected.
    fn test_api_create_boot() {
        test_block!(tb, "", {
            let mut clear = ClearDiskConfig::new();
            let guest = Guest::new(&mut clear);
            let mut workload_path = dirs::home_dir().unwrap();
            workload_path.push("workloads");

            let api_socket = temp_api_path(&guest.tmp_dir);

            let mut child = Command::new("target/debug/cloud-hypervisor")
                .args(&["--api-socket", &api_socket])
                .spawn()
                .unwrap();

            thread::sleep(std::time::Duration::new(1, 0));

            // Create the VM first
            let cpu_count: u8 = 4;
            let http_body = guest.api_create_body(cpu_count);
            curl_command(
                &api_socket,
                "PUT",
                "http://localhost/api/v1/vm.create",
                Some(&http_body),
            );

            // Then boot it
            curl_command(&api_socket, "PUT", "http://localhost/api/v1/vm.boot", None);
            thread::sleep(std::time::Duration::new(5, 0));

            // Check that the VM booted as expected
            aver_eq!(
                tb,
                guest.get_cpu_count().unwrap_or_default() as u8,
                cpu_count
            );
            aver!(tb, guest.get_total_memory().unwrap_or_default() > 491_000);
            aver!(tb, guest.get_entropy().unwrap_or_default() >= 900);

            guest
                .ssh_command("sudo shutdown -h now")
                .unwrap_or_default();
            thread::sleep(std::time::Duration::new(10, 0));

            let _ = child.kill();
            let _ = child.wait();

            Ok(())
        });
    }

    //    #[cfg_attr(not(feature = "mmio"), test)]
    //    // Start cloud-hypervisor with no VM parameters, only the API server running.
    //    // From the API: Create a VM, boot it and check that it looks as expected.
    //    // Then we pause the VM, check that it's no longer available.
    //    // Finally we resume the VM and check that it's available.
    //    fn test_api_pause_resume() {
    //        test_block!(tb, "", {
    //            let mut clear = ClearDiskConfig::new();
    //            let guest = Guest::new(&mut clear);
    //            let mut workload_path = dirs::home_dir().unwrap();
    //            workload_path.push("workloads");
    //
    //            let api_socket = temp_api_path(&guest.tmp_dir);
    //
    //            let mut child = Command::new("target/debug/cloud-hypervisor")
    //                .args(&["--api-socket", &api_socket])
    //                .spawn()
    //                .unwrap();
    //
    //            thread::sleep(std::time::Duration::new(1, 0));
    //
    //            // Create the VM first
    //            let cpu_count: u8 = 4;
    //            let http_body = guest.api_create_body(cpu_count);
    //            curl_command(
    //                &api_socket,
    //                "PUT",
    //                "http://localhost/api/v1/vm.create",
    //                Some(&http_body),
    //            );
    //
    //            // Then boot it
    //            curl_command(&api_socket, "PUT", "http://localhost/api/v1/vm.boot", None);
    //            thread::sleep(std::time::Duration::new(5, 0));
    //
    //            // Check that the VM booted as expected
    //            aver_eq!(
    //                tb,
    //                guest.get_cpu_count().unwrap_or_default() as u8,
    //                cpu_count
    //            );
    //            aver!(tb, guest.get_total_memory().unwrap_or_default() > 491_000);
    //            aver!(tb, guest.get_entropy().unwrap_or_default() >= 900);
    //
    //            // We now pause the VM
    //            curl_command(&api_socket, "PUT", "http://localhost/api/v1/vm.pause", None);
    //            thread::sleep(std::time::Duration::new(2, 0));
    //
    //            // SSH into the VM should fail
    //            aver!(
    //                tb,
    //                ssh_command_ip(
    //                    "grep -c processor /proc/cpuinfo",
    //                    &guest.network.guest_ip,
    //                    2,
    //                    5
    //                )
    //                .is_err()
    //            );
    //
    //            // Resume the VM
    //            curl_command(
    //                &api_socket,
    //                "PUT",
    //                "http://localhost/api/v1/vm.resume",
    //                None,
    //            );
    //            thread::sleep(std::time::Duration::new(2, 0));
    //
    //            // Now we should be able to SSH back in and get the right number of CPUs
    //            aver_eq!(
    //                tb,
    //                guest.get_cpu_count().unwrap_or_default() as u8,
    //                cpu_count
    //            );
    //
    //            guest
    //                .ssh_command("sudo shutdown -h now")
    //                .unwrap_or_default();
    //            thread::sleep(std::time::Duration::new(10, 0));
    //
    //            let _ = child.kill();
    //            let _ = child.wait();
    //
    //            Ok(())
    //        });
    //    }
}
