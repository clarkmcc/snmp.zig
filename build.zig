const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "snmp",
        .root_module = lib_mod,
    });

    lib.linkSystemLibrary("netsnmp");

    b.installArtifact(lib);

    // Unit tests
    const lib_unit_tests = b.addTest(.{
        .root_module = lib_mod,
    });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    // Integration tests
    const integration_test = b.addTest(.{
        .root_source_file = b.path("testing/integration/client.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration_test.root_module.addImport("snmp", lib_mod);
    const run_integration = b.addRunArtifact(integration_test);
    const integration_step = b.step("integration", "Run integration tests");
    integration_step.dependOn(&run_integration.step);
}
