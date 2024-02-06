const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    inline for (bpf_programs) |name| {
        const src = getBpfSource(name);
        const exe = addBpfProgram(b, .{
            .name = name,
            .bpf_name = name ++ ".bpf",
            .skel_name = name ++ ".skel.h",
            .root_source_file = src.root_source_file,
            .bpf_source_file = src.bpf_source_file,
            .target = target,
            .optimize = optimize,
        });
        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const step_name = "run_" ++ name;
        const step_desc = "Run " ++ name;
        const run_step = b.step(step_name, step_desc);
        run_step.dependOn(&run_cmd.step);
    }
    const exe = b.addExecutable(.{
        .name = "hijackee",
        .target = target,
        .optimize = optimize,
    });
    exe.linkLibC();
    exe.addCSourceFile(.{
        .file = .{ .path = "src/hijackee.c" },
        .flags = &.{},
    });
    b.installArtifact(exe);
}

pub const BpfProgramOptions = struct {
    name: []const u8,
    bpf_name: []const u8,
    skel_name: []const u8,
    target: std.Build.ResolvedTarget,
    root_source_file: std.Build.LazyPath,
    bpf_source_file: std.Build.LazyPath,
    optimize: std.builtin.OptimizeMode = .Debug,
};

pub fn addBpfProgram(
    b: *std.Build,
    options: BpfProgramOptions,
) *std.Build.Step.Compile {
    const target = options.target;
    const optimize = options.optimize;
    const t = target.result;
    const obj = b.addObject(.{
        .name = options.bpf_name,
        .target = b.resolveTargetQuery(.{
            .cpu_arch = switch (t.cpu.arch.endian()) {
                .big => .bpfeb,
                .little => .bpfel,
            },
            .os_tag = .freestanding,
        }),
        .optimize = .ReleaseFast,
    });
    const target_arch = switch (t.cpu.arch) {
        .x86, .x86_64 => "__TARGET_ARCH_x86",
        .aarch64 => "__TARGET_ARCH_arm64",
        else => @panic("unsupported arch"),
    };
    obj.defineCMacro(target_arch, null);
    obj.addIncludePath(.{ .path = "include" });
    obj.addCSourceFile(.{
        .file = options.bpf_source_file,
        .flags = &.{"-g"},
    });
    addOtherIncludePath(obj, b.dependency("bpf", .{
        .target = target,
        .optimize = optimize,
    }).artifact("bpf"));

    const cmd = b.addSystemCommand(&[_][]const u8{
        "bpftool",
        "gen",
        "skeleton",
    });
    cmd.addArtifactArg(obj);
    const skeleton = cmd.captureStdOut();
    cmd.captured_stdout.?.basename = options.skel_name;

    const exe = b.addExecutable(.{
        .name = options.name,
        .target = target,
        .optimize = optimize,
    });
    exe.addCSourceFile(.{
        .file = options.root_source_file,
        .flags = &.{},
    });
    exe.linkLibrary(b.dependency("bpf", .{
        .target = target,
        .optimize = optimize,
    }).artifact("bpf"));
    exe.addIncludePath(.{ .path = "include" });
    //exe.root_module.addAnonymousImport("bpf", .{
    //    .root_source_file = obj.getEmittedBin(),
    //});
    exe.addIncludePath(skeleton.dirname());
    return exe;
}

pub const BpfSource = struct {
    root_source_file: std.Build.LazyPath,
    bpf_source_file: std.Build.LazyPath,
};

pub fn getBpfSource(comptime name: []const u8) BpfSource {
    return .{
        .root_source_file = .{ .path = "src/" ++ name ++ ".c" },
        .bpf_source_file = .{ .path = "src/" ++ name ++ ".bpf.c" },
    };
}

pub fn addOtherIncludePath(
    self: *std.Build.Step.Compile,
    other: *std.Build.Step.Compile,
) void {
    const b = self.root_module.owner;
    self.root_module.include_dirs.append(
        b.allocator,
        .{ .other_step = other },
    ) catch @panic("OOM");
    for (other.installed_headers.items) |step| {
        other.step.dependOn(step);
    }
}

const bpf_programs = [_][]const u8{
    "bpfdos",
    "exechijack",
    "pidhide",
    "sudoadd",
    "textreplace",
    "textreplace2",
    "writeblocker",
};
