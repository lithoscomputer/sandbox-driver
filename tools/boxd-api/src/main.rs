//! Generates `sandbox-driver-boxd`'s gRPC code from boxd's published
//! `api.proto`, keeping only the calls the provider makes and the messages
//! they reach. Run it through `bin/boxd-api`, which fetches the proto.
//!
//! Usage: `boxd-api <api.proto> <out dir>`. Writes `client.rs` (messages and
//! the client) and `server.rs` (the server trait for the crate's fake,
//! reusing the client's messages).

use std::collections::{BTreeSet, HashMap};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::{env, fs};

use prost_types::{DescriptorProto, FileDescriptorSet};

/// The `BoxdApi` methods the provider calls. Keep sorted.
const USED: &[&str] = &[
    "CreateProxy",
    "CreateVm",
    "CreateVmFromSnapshot",
    "DeleteProxy",
    "DestroyVm",
    "Exec",
    "FsList",
    "FsMkdir",
    "FsRead",
    "FsRealpath",
    "FsWrite",
    "GetVm",
    "ListOrgs",
    "ListProxies",
    "ListRegions",
    "ListVms",
    "ResumeVm",
    "SetVmEgressAllow",
    "StartVm",
    "StopVm",
    "UpdateVmLabels",
    "WakeVm",
    "Whoami",
];
/// Calls only the live tests make, to put a machine to sleep or snapshot it.
const TEST_ONLY: &[&str] = &["CreateSnapshot", "DeleteSnapshot", "HibernateVm", "SuspendVm"];

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let (Some(proto), Some(out)) = (args.next(), args.next()) else {
        return Err("usage: boxd-api <api.proto> <out dir>".into());
    };
    let proto = PathBuf::from(proto);
    let include = proto.parent().unwrap_or(Path::new("."));
    let name = proto.file_name().ok_or("the proto path names no file")?;
    let mut set = protox::compile([name], [include])?;
    trim(&mut set)?;
    let out = PathBuf::from(out);
    for (file, client) in [("client", true), ("server", false)] {
        let dir = out.join(format!(".{file}"));
        fs::create_dir_all(&dir)?;
        let mut builder = tonic_prost_build::configure()
            .out_dir(&dir)
            .build_client(client)
            .build_server(!client)
            .build_transport(false);
        if !client {
            builder = builder.extern_path(".boxd.api.v1", "crate::runtime::api");
        }
        builder.compile_fds(set.clone())?;
        fs::rename(dir.join("boxd.api.v1.rs"), out.join(format!("{file}.rs")))?;
        fs::remove_dir(&dir)?;
    }
    Ok(())
}

/// Keeps the used methods and every message and enum they reach.
fn trim(set: &mut FileDescriptorSet) -> Result<(), Box<dyn Error>> {
    let [file] = set.file.as_mut_slice() else {
        return Err("expected one proto file".into());
    };
    let package = format!(".{}.", file.package());
    let mut reached = BTreeSet::new();
    let mut pending = Vec::new();
    for service in &mut file.service {
        service
            .method
            .retain(|method| USED.contains(&method.name()) || TEST_ONLY.contains(&method.name()));
        for method in &service.method {
            pending.push(method.input_type().to_owned());
            pending.push(method.output_type().to_owned());
        }
    }
    let messages: HashMap<String, DescriptorProto> = file
        .message_type
        .iter()
        .map(|message| (format!("{package}{}", message.name()), message.clone()))
        .collect();
    while let Some(name) = pending.pop() {
        // Nested types and map entries live under their top-level message.
        let top = name
            .strip_prefix(&package)
            .and_then(|rest| rest.split('.').next())
            .map(|top| format!("{package}{top}"))
            .unwrap_or(name);
        if !reached.insert(top.clone()) {
            continue;
        }
        if let Some(message) = messages.get(&top) {
            collect(message, &mut pending);
        }
    }
    let kept = |name: &str| reached.contains(&format!("{package}{name}"));
    file.message_type.retain(|message| kept(message.name()));
    file.enum_type.retain(|kind| kept(kind.name()));
    // Comments refer to source positions that no longer line up.
    file.source_code_info = None;
    Ok(())
}

fn collect(message: &DescriptorProto, pending: &mut Vec<String>) {
    for field in &message.field {
        if !field.type_name().is_empty() {
            pending.push(field.type_name().to_owned());
        }
    }
    for nested in &message.nested_type {
        collect(nested, pending);
    }
}
