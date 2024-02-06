const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const t = target.result;
    const obj = b.addObject(.{
        .name = "exechijack.bpf",
        .target = b.resolveTargetQuery(.{
            .cpu_arch = switch (t.cpu.arch.endian()) {
                .big => .bpfeb,
                .little => .bpfel,
            },
            .os_tag = .freestanding,
        }),
        .optimize = .ReleaseFast,
    });
    obj.addIncludePath(.{ .path = "include" });
    obj.addCSourceFile(.{
        .file = .{ .path = "src/exechijack.bpf.c" },
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
    cmd.captured_stdout.?.basename = "exechijack.skel.h";

    const exe = b.addExecutable(.{
        .name = "bad-bpf",
        .target = target,
        .optimize = optimize,
    });
    exe.addCSourceFile(.{
        .file = .{ .path = "src/exechijack.c" },
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
