from pathlib import Path

from migate.egress import lifecycle as lifecycle_module
from migate.egress.lifecycle import EgressLifecycleResult, bring_down_egress, bring_up_egress
from migate.egress.openvpn_backend import build_openvpn_tunnel_start_plan, build_openvpn_tunnel_stop_plan
from migate.egress.tunnel_backend import TunnelStartPlan, TunnelStopPlan
from migate.xray.apply_cli import XrayApplyResult
from migate.xray.service_cli import XrayServiceSaveResult
from migate.xray.systemctl_cli import ALLOWED_XRAY_TUN_SERVICE_NAME, SystemctlActionResult
from migate.xray.tun_config import XrayTunConfigSaveResult
from migate.xray.validator import XrayValidationResult
from migate.routing.policy_cleanup import build_policy_routing_cleanup_plan
from migate.routing.policy_plan import build_policy_routing_plan
from migate.config import MiGateConfig


class FakeCommandResult:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _start_plan():
    return build_openvpn_tunnel_start_plan(MiGateConfig())


def _routing_plan():
    return build_policy_routing_plan(MiGateConfig())


def _cleanup_plan():
    return build_policy_routing_cleanup_plan(MiGateConfig())


def _stop_plan(pid_file: Path):
    return build_openvpn_tunnel_stop_plan(pid_file)


def test_bring_up_egress_rejects_without_side_effect_gate(tmp_path: Path):
    calls: list[list[str]] = []

    result = bring_up_egress(
        _start_plan(),
        _routing_plan(),
        runner=lambda argv: calls.append(argv),
    )

    assert result == EgressLifecycleResult(
        status="rejected",
        message="allow_side_effects must be true to bring egress up",
        phases=[],
        commands_executed=[],
        performed_side_effects=False,
    )
    assert calls == []


def test_bring_up_egress_starts_openvpn_then_applies_policy_routing():
    calls: list[list[str]] = []
    start_plan = _start_plan()
    routing_plan = _routing_plan()

    def runner(argv: list[str]) -> FakeCommandResult:
        calls.append(argv)
        return FakeCommandResult(returncode=0, stdout="ok", stderr="")

    result = bring_up_egress(
        start_plan,
        routing_plan,
        runner=runner,
        allow_side_effects=True,
        config_exists=lambda path: path in (start_plan.required_paths or []),
        ensure_directory=lambda path: None,
    )

    assert calls == [start_plan.command, *routing_plan.commands]
    assert result.status == "up"
    assert result.message == "egress brought up"
    assert [phase.name for phase in result.phases] == ["tunnel_start", "policy_routing_apply"]
    assert [phase.status for phase in result.phases] == ["started", "applied"]
    assert result.commands_executed == [" ".join(start_plan.command), *[" ".join(command) for command in routing_plan.commands]]
    assert result.performed_side_effects is True


def test_bring_up_egress_stops_before_openvpn_when_runtime_config_is_missing():
    calls: list[list[str]] = []
    start_plan = _start_plan()
    routing_plan = _routing_plan()

    result = bring_up_egress(
        start_plan,
        routing_plan,
        runner=lambda argv: calls.append(argv) or FakeCommandResult(0),
        allow_side_effects=True,
        config_exists=lambda path: False,
        ensure_directory=lambda path: None,
    )

    assert calls == []
    assert result.status == "failed"
    assert result.message == f"egress up preflight failed; openvpn runtime path is missing: {(start_plan.required_paths or [])[0]}"
    assert [phase.name for phase in result.phases] == ["tunnel_preflight"]
    assert [phase.status for phase in result.phases] == ["failed"]
    assert result.commands_executed == []
    assert result.performed_side_effects is False


def test_bring_up_egress_creates_runtime_parent_directories_before_starting_openvpn():
    calls: list[list[str]] = []
    ensured: list[Path] = []
    start_plan = _start_plan()
    routing_plan = _routing_plan()

    def runner(argv: list[str]) -> FakeCommandResult:
        calls.append(argv)
        return FakeCommandResult(returncode=0, stdout="ok", stderr="")

    result = bring_up_egress(
        start_plan,
        routing_plan,
        runner=runner,
        allow_side_effects=True,
        config_exists=lambda path: True,
        ensure_directory=lambda path: ensured.append(path),
    )

    assert result.status == "up"
    assert ensured == [Path("/var/lib/migate/runtime"), Path("/var/log/migate")]
    assert calls == [start_plan.command, *routing_plan.commands]


def test_bring_up_egress_stops_before_routing_when_openvpn_start_fails():
    calls: list[list[str]] = []
    start_plan = _start_plan()
    routing_plan = _routing_plan()

    def runner(argv: list[str]) -> FakeCommandResult:
        calls.append(argv)
        return FakeCommandResult(returncode=1, stdout="", stderr="openvpn failed")

    result = bring_up_egress(
        start_plan,
        routing_plan,
        runner=runner,
        allow_side_effects=True,
        config_exists=lambda path: True,
        ensure_directory=lambda path: None,
    )

    assert calls == [start_plan.command]
    assert result.status == "failed"
    assert result.message == "egress up stopped before routing; openvpn tunnel start failed"
    assert [phase.name for phase in result.phases] == ["tunnel_start"]
    assert result.commands_executed == [" ".join(start_plan.command)]
    assert result.performed_side_effects is True


def test_bring_up_egress_accepts_separate_openvpn_and_routing_runners():
    start_plan = _start_plan()
    routing_plan = _routing_plan()
    openvpn_calls: list[list[str]] = []
    routing_calls: list[list[str]] = []

    def openvpn_runner(argv: list[str]) -> FakeCommandResult:
        openvpn_calls.append(argv)
        assert argv[0] == "openvpn"
        return FakeCommandResult(returncode=0, stdout="vpn ok", stderr="")

    def routing_runner(argv: list[str]) -> FakeCommandResult:
        routing_calls.append(argv)
        assert argv[0] == "ip"
        return FakeCommandResult(returncode=0, stdout="route ok", stderr="")

    result = bring_up_egress(
        start_plan,
        routing_plan,
        openvpn_runner=openvpn_runner,
        routing_runner=routing_runner,
        allow_side_effects=True,
        config_exists=lambda path: True,
        ensure_directory=lambda path: None,
    )

    assert openvpn_calls == [start_plan.command]
    assert routing_calls == routing_plan.commands
    assert result.status == "up"
    assert result.commands_executed == [" ".join(start_plan.command), *[" ".join(command) for command in routing_plan.commands]]


def test_bring_up_egress_accepts_non_openvpn_tunnel_backend_plan():
    tunnel_plan = TunnelStartPlan(
        backend="wireguard",
        command=["wg-quick", "up", "migate0"],
        runtime_paths=["/etc/wireguard/migate0.conf", "/var/log/migate/wireguard.log"],
    )
    routing_plan = _routing_plan()
    calls: list[list[str]] = []
    ensured: list[Path] = []

    result = bring_up_egress(
        tunnel_plan,
        routing_plan,
        runner=lambda argv: calls.append(argv) or FakeCommandResult(0, stdout="ok", stderr=""),
        allow_side_effects=True,
        config_exists=lambda path: path == "/etc/wireguard/migate0.conf",
        ensure_directory=lambda path: ensured.append(path),
    )

    assert calls == [tunnel_plan.command, *routing_plan.commands]
    assert result.status == "up"
    assert [phase.name for phase in result.phases] == ["tunnel_start", "policy_routing_apply"]
    assert ensured == [Path("/etc/wireguard"), Path("/var/log/migate")]


def test_bring_up_egress_xray_tun_runs_validation_gated_apply_before_policy_routing():
    tunnel_plan = TunnelStartPlan(
        backend="xray-tun",
        command=["systemctl", "start", ALLOWED_XRAY_TUN_SERVICE_NAME],
        runtime_paths=["/etc/migate/xray/config.json", "/var/log/migate/xray-tun.log"],
        required_paths=["/etc/migate/xray/config.json"],
    )
    routing_plan = _routing_plan()
    apply_calls: list[str] = []
    routing_calls: list[list[str]] = []

    def xray_tun_start_runner(config_path: str) -> XrayApplyResult:
        apply_calls.append(config_path)
        return XrayApplyResult(
            status="success",
            message="xray tun config validated and service started",
            config_path=config_path,
            validation=XrayValidationResult("valid", 0, "ok", ""),
            systemctl_results=[
                SystemctlActionResult("success", "daemon-reload", ALLOWED_XRAY_TUN_SERVICE_NAME, ["systemctl", "daemon-reload"], 0, "reload ok", "", True),
                SystemctlActionResult("success", "start", ALLOWED_XRAY_TUN_SERVICE_NAME, ["systemctl", "start", ALLOWED_XRAY_TUN_SERVICE_NAME], 0, "start ok", "", True),
            ],
            performed_side_effects=True,
        )

    result = bring_up_egress(
        tunnel_plan,
        routing_plan,
        xray_tun_start_runner=xray_tun_start_runner,
        xray_tun_interface_ready=lambda name: True,
        routing_runner=lambda argv: routing_calls.append(argv) or FakeCommandResult(0, stdout="route ok", stderr=""),
        allow_side_effects=True,
        config_exists=lambda path: path == "/etc/migate/xray/config.json",
        ensure_directory=lambda path: None,
    )

    assert apply_calls == ["/etc/migate/xray/config.json"]
    assert routing_calls == routing_plan.commands
    assert result.status == "up"
    assert [phase.name for phase in result.phases] == ["xray_tun_apply_start", "xray_tun_interface_ready", "policy_routing_apply"]
    assert [phase.status for phase in result.phases] == ["success", "ready", "applied"]
    assert result.commands_executed == [
        "systemctl daemon-reload",
        f"systemctl start {ALLOWED_XRAY_TUN_SERVICE_NAME}",
        *[" ".join(command) for command in routing_plan.commands],
    ]
    assert result.performed_side_effects is True


def test_bring_up_egress_xray_tun_bootstraps_generated_runtime_artifacts_on_fresh_host():
    tunnel_plan = TunnelStartPlan(
        backend="xray-tun",
        command=["systemctl", "start", ALLOWED_XRAY_TUN_SERVICE_NAME],
        runtime_paths=["/etc/migate/xray/config.json", "/etc/systemd/system/migate-xray-tun.service", "/var/log/migate/xray-tun.log"],
        required_paths=["/etc/migate/xray/config.json", "/etc/systemd/system/migate-xray-tun.service"],
    )
    routing_plan = _routing_plan()
    apply_calls: list[str] = []

    def xray_tun_start_runner(config_path: str) -> XrayApplyResult:
        apply_calls.append(config_path)
        return XrayApplyResult(
            status="success",
            message="xray tun config generated, validated, and service started",
            config_path=config_path,
            validation=XrayValidationResult("valid", 0, "ok", ""),
            systemctl_results=[
                SystemctlActionResult("success", "daemon-reload", ALLOWED_XRAY_TUN_SERVICE_NAME, ["systemctl", "daemon-reload"], 0, "reload ok", "", True),
                SystemctlActionResult("success", "start", ALLOWED_XRAY_TUN_SERVICE_NAME, ["systemctl", "start", ALLOWED_XRAY_TUN_SERVICE_NAME], 0, "start ok", "", True),
            ],
            performed_side_effects=True,
        )

    result = bring_up_egress(
        tunnel_plan,
        routing_plan,
        xray_tun_start_runner=xray_tun_start_runner,
        xray_tun_interface_ready=lambda name: True,
        routing_runner=lambda argv: FakeCommandResult(0, stdout="route ok", stderr=""),
        allow_side_effects=True,
        config_exists=lambda path: False,
        ensure_directory=lambda path: None,
    )

    assert apply_calls == ["/etc/migate/xray/config.json"]
    assert result.status == "up"
    assert [phase.name for phase in result.phases] == ["xray_tun_apply_start", "xray_tun_interface_ready", "policy_routing_apply"]


def test_bootstrap_xray_tun_start_runner_saves_config_and_service_before_starting(monkeypatch):
    calls: list[tuple[str, str]] = []

    def fake_save_config(config, target, *, yes, allow_system_changes):
        calls.append(("save_config", str(target)))
        assert isinstance(config, MiGateConfig)
        assert yes is True
        assert allow_system_changes is True
        return XrayTunConfigSaveResult(
            status="saved",
            message="xray tun config saved and validated",
            target=Path(target),
            validation_status="valid",
            performed_side_effects=True,
        )

    def fake_save_service(target, *, yes, allow_system_changes, config_path):
        calls.append(("save_service", str(target)))
        assert yes is True
        assert allow_system_changes is True
        assert config_path == "/etc/migate/xray/config.json"
        return XrayServiceSaveResult(
            status="saved",
            message="xray tun service unit saved; daemon-reload not run",
            target=Path(target),
            performed_side_effects=True,
            systemctl_commands_executed=[],
        )

    def fake_apply(config_path, *, yes, allow_system_changes):
        calls.append(("apply_start", str(config_path)))
        assert yes is True
        assert allow_system_changes is True
        return XrayApplyResult(
            status="success",
            message="xray tun config validated and service started",
            config_path=str(config_path),
            validation=XrayValidationResult("valid", 0, "ok", ""),
            systemctl_results=[
                SystemctlActionResult("success", "daemon-reload", ALLOWED_XRAY_TUN_SERVICE_NAME, ["systemctl", "daemon-reload"], 0, "reload ok", "", True),
                SystemctlActionResult("success", "start", ALLOWED_XRAY_TUN_SERVICE_NAME, ["systemctl", "start", ALLOWED_XRAY_TUN_SERVICE_NAME], 0, "start ok", "", True),
            ],
            performed_side_effects=True,
        )

    monkeypatch.setattr(lifecycle_module, "save_xray_tun_config", fake_save_config)
    monkeypatch.setattr(lifecycle_module, "save_xray_tun_service_unit", fake_save_service)
    monkeypatch.setattr(lifecycle_module, "apply_validated_xray_tun_start", fake_apply)

    result = lifecycle_module._default_xray_tun_start_runner("/etc/migate/xray/config.json")

    assert result.status == "success"
    assert calls == [
        ("save_config", "/etc/migate/xray/config.json"),
        ("save_service", "/etc/systemd/system/migate-xray-tun.service"),
        ("apply_start", "/etc/migate/xray/config.json"),
    ]


def test_bootstrap_xray_tun_start_runner_stops_when_config_save_fails(monkeypatch):
    calls: list[str] = []

    def fake_save_config(config, target, *, yes, allow_system_changes):
        calls.append("save_config")
        return XrayTunConfigSaveResult(
            status="invalid",
            message="xray tun config validation failed; removed invalid new config",
            target=Path(target),
            validation_status="invalid",
            performed_side_effects=True,
            rollback_performed=True,
        )

    monkeypatch.setattr(lifecycle_module, "save_xray_tun_config", fake_save_config)
    monkeypatch.setattr(lifecycle_module, "save_xray_tun_service_unit", lambda *args, **kwargs: calls.append("save_service"))
    monkeypatch.setattr(lifecycle_module, "apply_validated_xray_tun_start", lambda *args, **kwargs: calls.append("apply_start"))

    result = lifecycle_module._default_xray_tun_start_runner("/etc/migate/xray/config.json")

    assert result.status == "invalid_config"
    assert result.message == "xray tun config bootstrap failed; service start skipped"
    assert result.validation.status == "invalid"
    assert result.systemctl_results == []
    assert result.performed_side_effects is True
    assert calls == ["save_config"]


def test_bootstrap_xray_tun_start_runner_stops_when_service_save_fails(monkeypatch):
    calls: list[str] = []

    monkeypatch.setattr(
        lifecycle_module,
        "save_xray_tun_config",
        lambda *args, **kwargs: calls.append("save_config")
        or XrayTunConfigSaveResult(
            status="saved",
            message="xray tun config saved and validated",
            target=Path("/etc/migate/xray/config.json"),
            validation_status="valid",
            performed_side_effects=True,
        ),
    )
    monkeypatch.setattr(
        lifecycle_module,
        "save_xray_tun_service_unit",
        lambda *args, **kwargs: calls.append("save_service")
        or XrayServiceSaveResult(
            status="rejected",
            message="xray tun service save requires yes=True and allow_system_changes=True",
            target=Path("/etc/systemd/system/migate-xray-tun.service"),
            performed_side_effects=False,
            systemctl_commands_executed=[],
        ),
    )
    monkeypatch.setattr(lifecycle_module, "apply_validated_xray_tun_start", lambda *args, **kwargs: calls.append("apply_start"))

    result = lifecycle_module._default_xray_tun_start_runner("/etc/migate/xray/config.json")

    assert result.status == "systemctl_failed"
    assert result.message == "xray tun service bootstrap failed; service start skipped"
    assert result.validation.status == "valid"
    assert result.systemctl_results == []
    assert result.performed_side_effects is True
    assert calls == ["save_config", "save_service"]


def test_bring_up_egress_xray_tun_stops_before_policy_routing_when_apply_fails():
    tunnel_plan = TunnelStartPlan(
        backend="xray-tun",
        command=["systemctl", "start", ALLOWED_XRAY_TUN_SERVICE_NAME],
        runtime_paths=["/etc/migate/xray/config.json"],
        required_paths=["/etc/migate/xray/config.json"],
    )
    routing_calls: list[list[str]] = []

    def xray_tun_start_runner(config_path: str) -> XrayApplyResult:
        return XrayApplyResult(
            status="systemctl_failed",
            message="xray tun start failed",
            config_path=config_path,
            validation=XrayValidationResult("valid", 0, "ok", ""),
            systemctl_results=[
                SystemctlActionResult("success", "daemon-reload", ALLOWED_XRAY_TUN_SERVICE_NAME, ["systemctl", "daemon-reload"], 0, "reload ok", "", True),
                SystemctlActionResult("failed", "start", ALLOWED_XRAY_TUN_SERVICE_NAME, ["systemctl", "start", ALLOWED_XRAY_TUN_SERVICE_NAME], 1, "", "start failed", True),
            ],
            performed_side_effects=True,
        )

    result = bring_up_egress(
        tunnel_plan,
        _routing_plan(),
        xray_tun_start_runner=xray_tun_start_runner,
        routing_runner=lambda argv: routing_calls.append(argv) or FakeCommandResult(0),
        allow_side_effects=True,
        config_exists=lambda path: True,
        ensure_directory=lambda path: None,
    )

    assert routing_calls == []
    assert result.status == "failed"
    assert result.message == "egress up stopped before routing; xray-tun apply start failed"
    assert [phase.name for phase in result.phases] == ["xray_tun_apply_start"]
    assert result.commands_executed == ["systemctl daemon-reload", f"systemctl start {ALLOWED_XRAY_TUN_SERVICE_NAME}"]
    assert result.performed_side_effects is True


def test_bring_up_egress_xray_tun_waits_for_interface_before_policy_routing():
    tunnel_plan = TunnelStartPlan(
        backend="xray-tun",
        command=["systemctl", "start", ALLOWED_XRAY_TUN_SERVICE_NAME],
        runtime_paths=["/etc/migate/xray/config.json"],
        required_paths=["/etc/migate/xray/config.json"],
    )
    events: list[str] = []

    def xray_tun_start_runner(config_path: str) -> XrayApplyResult:
        events.append(f"start:{config_path}")
        return XrayApplyResult(
            status="success",
            message="started",
            config_path=config_path,
            validation=XrayValidationResult("valid", 0, "ok", ""),
            systemctl_results=[SystemctlActionResult("success", "start", ALLOWED_XRAY_TUN_SERVICE_NAME, ["systemctl", "start", ALLOWED_XRAY_TUN_SERVICE_NAME], 0, "", "", True)],
            performed_side_effects=True,
        )

    result = bring_up_egress(
        tunnel_plan,
        _routing_plan(),
        xray_tun_start_runner=xray_tun_start_runner,
        xray_tun_interface_ready=lambda name: events.append(f"ready:{name}") or True,
        routing_runner=lambda argv: events.append("route:" + " ".join(argv)) or FakeCommandResult(0),
        allow_side_effects=True,
        config_exists=lambda path: True,
        ensure_directory=lambda path: None,
    )

    assert result.status == "up"
    assert events == [
        "start:/etc/migate/xray/config.json",
        "ready:tun-migate",
        "route:ip rule add fwmark 0x66 table 100",
        "route:ip route add default dev tun-migate table 100",
    ]
    assert [phase.name for phase in result.phases] == ["xray_tun_apply_start", "xray_tun_interface_ready", "policy_routing_apply"]
    assert [phase.status for phase in result.phases] == ["success", "ready", "applied"]


def test_bring_down_egress_rejects_without_side_effect_gate(tmp_path: Path):
    calls: list[list[str]] = []

    result = bring_down_egress(
        _cleanup_plan(),
        _stop_plan(tmp_path / "openvpn.pid"),
        runner=lambda argv: calls.append(argv),
    )

    assert result == EgressLifecycleResult(
        status="rejected",
        message="allow_side_effects must be true to bring egress down",
        phases=[],
        commands_executed=[],
        performed_side_effects=False,
    )
    assert calls == []


def test_bring_down_egress_cleans_policy_routing_then_stops_openvpn(tmp_path: Path):
    pid_file = tmp_path / "openvpn.pid"
    pid_file.write_text("4321\n", encoding="utf-8")
    cleanup_plan = _cleanup_plan()
    stop_plan = _stop_plan(pid_file)
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> FakeCommandResult:
        calls.append(argv)
        return FakeCommandResult(returncode=0, stdout="ok", stderr="")

    result = bring_down_egress(cleanup_plan, stop_plan, runner=runner, allow_side_effects=True)

    assert calls == [*cleanup_plan.commands, stop_plan.command]
    assert result.status == "down"
    assert result.message == "egress brought down"
    assert [phase.name for phase in result.phases] == ["policy_routing_cleanup", "tunnel_stop"]
    assert [phase.status for phase in result.phases] == ["applied", "stopped"]
    assert result.commands_executed == [*[" ".join(command) for command in cleanup_plan.commands], " ".join(stop_plan.command)]
    assert result.performed_side_effects is True


def test_bring_down_egress_accepts_separate_cleanup_and_stop_runners(tmp_path: Path):
    pid_file = tmp_path / "openvpn.pid"
    pid_file.write_text("4321\n", encoding="utf-8")
    cleanup_plan = _cleanup_plan()
    stop_plan = _stop_plan(pid_file)
    cleanup_calls: list[list[str]] = []
    stop_calls: list[list[str]] = []

    def cleanup_runner(argv: list[str]) -> FakeCommandResult:
        cleanup_calls.append(argv)
        assert argv[0] == "ip"
        return FakeCommandResult(returncode=0, stdout="cleanup ok", stderr="")

    def stop_runner(argv: list[str]) -> FakeCommandResult:
        stop_calls.append(argv)
        assert argv == stop_plan.command
        return FakeCommandResult(returncode=0, stdout="stop ok", stderr="")

    result = bring_down_egress(
        cleanup_plan,
        stop_plan,
        cleanup_runner=cleanup_runner,
        stop_runner=stop_runner,
        allow_side_effects=True,
    )

    assert cleanup_calls == cleanup_plan.commands
    assert stop_calls == [stop_plan.command]
    assert result.status == "down"
    assert result.commands_executed == [*[" ".join(command) for command in cleanup_plan.commands], " ".join(stop_plan.command)]


def test_bring_down_egress_accepts_non_openvpn_tunnel_backend_stop_plan():
    cleanup_plan = _cleanup_plan()
    stop_plan = TunnelStopPlan(backend="wireguard", command=["wg-quick", "down", "migate0"])
    calls: list[list[str]] = []

    result = bring_down_egress(
        cleanup_plan,
        stop_plan,
        runner=lambda argv: calls.append(argv) or FakeCommandResult(0, stdout="ok", stderr=""),
        allow_side_effects=True,
    )

    assert calls == [*cleanup_plan.commands, stop_plan.command]
    assert result.status == "down"
    assert [phase.name for phase in result.phases] == ["policy_routing_cleanup", "tunnel_stop"]
    assert result.commands_executed == [*[" ".join(command) for command in cleanup_plan.commands], "wg-quick down migate0"]


def test_bring_down_egress_xray_tun_cleans_policy_routing_then_stops_service():
    cleanup_plan = _cleanup_plan()
    stop_plan = TunnelStopPlan(backend="xray-tun", command=["systemctl", "stop", ALLOWED_XRAY_TUN_SERVICE_NAME])
    cleanup_calls: list[list[str]] = []
    stop_calls: list[str] = []

    def xray_tun_stop_runner() -> SystemctlActionResult:
        stop_calls.append("stop")
        return SystemctlActionResult(
            status="success",
            action="stop",
            service=ALLOWED_XRAY_TUN_SERVICE_NAME,
            command=["systemctl", "stop", ALLOWED_XRAY_TUN_SERVICE_NAME],
            returncode=0,
            stdout="stopped",
            stderr="",
            performed_side_effects=True,
        )

    result = bring_down_egress(
        cleanup_plan,
        stop_plan,
        cleanup_runner=lambda argv: cleanup_calls.append(argv) or FakeCommandResult(0, stdout="cleanup ok", stderr=""),
        xray_tun_stop_runner=xray_tun_stop_runner,
        allow_side_effects=True,
    )

    assert cleanup_calls == cleanup_plan.commands
    assert stop_calls == ["stop"]
    assert result.status == "down"
    assert [phase.name for phase in result.phases] == ["policy_routing_cleanup", "xray_tun_stop"]
    assert [phase.status for phase in result.phases] == ["applied", "success"]
    assert result.commands_executed == [*[" ".join(command) for command in cleanup_plan.commands], f"systemctl stop {ALLOWED_XRAY_TUN_SERVICE_NAME}"]
    assert result.performed_side_effects is True


def test_bring_down_egress_xray_tun_stops_before_service_stop_when_cleanup_fails():
    cleanup_plan = _cleanup_plan()
    stop_plan = TunnelStopPlan(backend="xray-tun", command=["systemctl", "stop", ALLOWED_XRAY_TUN_SERVICE_NAME])
    cleanup_calls: list[list[str]] = []
    stop_calls: list[str] = []

    result = bring_down_egress(
        cleanup_plan,
        stop_plan,
        cleanup_runner=lambda argv: cleanup_calls.append(argv) or FakeCommandResult(2, stdout="", stderr="cleanup failed"),
        xray_tun_stop_runner=lambda: stop_calls.append("stop") or SystemctlActionResult("success", "stop", ALLOWED_XRAY_TUN_SERVICE_NAME, [], 0, "", "", True),
        allow_side_effects=True,
    )

    assert cleanup_calls == [cleanup_plan.commands[0]]
    assert stop_calls == []
    assert result.status == "failed"
    assert result.message == "egress down stopped before xray-tun tunnel stop; routing cleanup failed"
    assert [phase.name for phase in result.phases] == ["policy_routing_cleanup"]


def test_bring_down_egress_stops_before_openvpn_stop_when_cleanup_fails(tmp_path: Path):
    pid_file = tmp_path / "openvpn.pid"
    pid_file.write_text("4321\n", encoding="utf-8")
    cleanup_plan = _cleanup_plan()
    stop_plan = _stop_plan(pid_file)
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> FakeCommandResult:
        calls.append(argv)
        return FakeCommandResult(returncode=2, stdout="", stderr="cleanup failed")

    result = bring_down_egress(cleanup_plan, stop_plan, runner=runner, allow_side_effects=True)

    assert calls == [cleanup_plan.commands[0]]
    assert result.status == "failed"
    assert result.message == "egress down stopped before openvpn tunnel stop; routing cleanup failed"
    assert [phase.name for phase in result.phases] == ["policy_routing_cleanup"]
    assert result.commands_executed == [" ".join(cleanup_plan.commands[0])]
    assert result.performed_side_effects is True
