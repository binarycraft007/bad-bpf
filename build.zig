const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const bpf_dep = b.dependency("bpf", .{
        .target = target,
        .optimize = optimize,
    });
    const lib = b.addStaticLibrary(.{
        .name = "bpf",
        .target = target,
        .optimize = optimize,
    });
    lib.linkLibC();
    lib.defineCMacro("_LARGEFILE64_SOURCE", null);
    lib.defineCMacro("_FILE_OFFSET_BITS", "64");
    lib.root_module.linkLibrary(b.dependency("elf", .{
        .target = target,
        .optimize = optimize,
    }).artifact("elf"));
    lib.addCSourceFiles(.{
        .dependency = bpf_dep,
        .files = &libbpf_src,
        .flags = &.{},
    });
    inline for (header_files) |file| {
        lib.installHeadersDirectoryOptions(.{
            .source_dir = bpf_dep.path("src"),
            .install_dir = .header,
            .install_subdir = "bpf",
            .include_extensions = &.{file},
        });
    }
    inline for (uapi_files) |file| {
        lib.installHeadersDirectoryOptions(.{
            .source_dir = bpf_dep.path(uapi_header),
            .install_dir = .header,
            .install_subdir = "linux",
            .include_extensions = &.{file},
        });
    }
    lib.installHeadersDirectoryOptions(.{
        .source_dir = .{ .path = "include" },
        .install_dir = .header,
        .install_subdir = "",
        .include_extensions = &.{"vmlinux.h"},
    });
    lib.addIncludePath(bpf_dep.path("src"));
    lib.addIncludePath(bpf_dep.path("include"));
    lib.addIncludePath(bpf_dep.path("include/uapi"));
    lib.addIncludePath(.{ .path = "include" });
    b.installArtifact(lib);

    const exe = b.addExecutable(.{
        .name = "bad-bpf",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const lib_unit_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/root.zig" },
        .target = target,
        .optimize = optimize,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const exe_unit_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);
}

const uapi_header = "include/uapi/linux";

const libbpf_src = [_][]const u8{
    "src/bpf.c",
    "src/btf.c",
    "src/libbpf.c",
    "src/libbpf_errno.c",
    "src/netlink.c",
    "src/nlattr.c",
    "src/str_error.c",
    "src/libbpf_probes.c",
    "src/bpf_prog_linfo.c",
    "src/btf_dump.c",
    "src/hashmap.c",
    "src/ringbuf.c",
    "src/strset.c",
    "src/linker.c",
    "src/gen_loader.c",
    "src/relo_core.c",
    "src/usdt.c",
    "src/zip.c",
    "src/elf.c",
    "src/features.c",
};

const header_files = [_][]const u8{
    "bpf.h",
    "libbpf.h ",
    "btf.h",
    "libbpf_common.h",
    "libbpf_legacy.h",
    "bpf_helpers.h",
    "bpf_helper_defs.h",
    "bpf_tracing.h",
    "bpf_endian.h",
    "bpf_core_read.h",
    "skel_internal.h",
    "libbpf_version.h",
    "usdt.bpf.h",
};

const uapi_files = [_][]const u8{
    "bpf.h",
    "bpf_common.h",
    "btf.h",
};
