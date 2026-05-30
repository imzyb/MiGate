from migate.config import MiGateConfig
from migate.xray.install_plan import XrayInstallPlan, build_xray_install_plan, normalize_machine_arch


def test_normalize_machine_arch_maps_common_linux_architectures():
    assert normalize_machine_arch("x86_64") == "64"
    assert normalize_machine_arch("amd64") == "64"
    assert normalize_machine_arch("aarch64") == "arm64-v8a"
    assert normalize_machine_arch("arm64") == "arm64-v8a"


def test_normalize_machine_arch_rejects_unknown_architecture():
    try:
        normalize_machine_arch("mips64")
    except ValueError as exc:
        assert "unsupported architecture" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_build_xray_install_plan_uses_config_paths_and_safe_preview_steps():
    config = MiGateConfig()

    plan = build_xray_install_plan(config, system="Linux", machine="aarch64", version="v1.8.24")

    assert isinstance(plan, XrayInstallPlan)
    assert plan.version == "v1.8.24"
    assert plan.system == "linux"
    assert plan.arch == "arm64-v8a"
    assert plan.bin_path == "/usr/local/bin/xray"
    assert plan.config_dir == "/etc/migate/xray"
    assert plan.archive_name == "Xray-linux-arm64-v8a.zip"
    assert plan.download_url == "https://github.com/XTLS/Xray-core/releases/download/v1.8.24/Xray-linux-arm64-v8a.zip"
    assert plan.performs_side_effects is False
    assert plan.commands == []
    assert [step.action for step in plan.steps] == [
        "download_archive",
        "verify_archive",
        "extract_binary",
        "install_binary",
        "chmod_executable",
        "verify_version",
    ]


def test_build_xray_install_plan_can_render_human_readable_preview():
    plan = build_xray_install_plan(MiGateConfig(), system="Linux", machine="x86_64", version="latest")

    preview = plan.to_preview()

    assert "Xray 安装计划" in preview
    assert "版本：latest" in preview
    assert "架构：linux-64" in preview
    assert "目标路径：/usr/local/bin/xray" in preview
    assert "不会执行任何安装命令" in preview
    assert "下载 xray-core zip" in preview
    assert "xray version 验证" in preview
