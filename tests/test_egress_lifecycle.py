from pathlib import Path

from migate.egress.lifecycle import EgressLifecycleResult, bring_down_egress, bring_up_egress
from migate.routing.policy_cleanup import build_policy_routing_cleanup_plan
from migate.routing.policy_plan import build_policy_routing_plan
from migate.vpn.process_plan import build_openvpn_start_plan
from migate.vpn.process_stop import build_openvpn_stop_plan
from migate.config import MiGateConfig


class FakeCommandResult:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _start_plan():
    return build_openvpn_start_plan(
        MiGateConfig(),
        config_path="/var/lib/migate/runtime/active.ovpn",
        pid_path="/var/lib/migate/runtime/openvpn.pid",
        status_path="/var/lib/migate/runtime/status.json",
        log_path="/var/log/migate/openvpn.log",
    )


def _routing_plan():
    return build_policy_routing_plan(MiGateConfig())


def _cleanup_plan():
    return build_policy_routing_cleanup_plan(MiGateConfig())


def _stop_plan(pid_file: Path):
    return build_openvpn_stop_plan(pid_file=pid_file)


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
        config_exists=lambda path: path == start_plan.config_path,
        ensure_directory=lambda path: None,
    )

    assert calls == [start_plan.command, *routing_plan.commands]
    assert result.status == "up"
    assert result.message == "egress brought up"
    assert [phase.name for phase in result.phases] == ["openvpn_start", "policy_routing_apply"]
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
    assert result.message == f"egress up preflight failed; OpenVPN config is missing: {start_plan.config_path}"
    assert [phase.name for phase in result.phases] == ["openvpn_preflight"]
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
    assert result.message == "egress up stopped before routing; OpenVPN start failed"
    assert [phase.name for phase in result.phases] == ["openvpn_start"]
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

    assert calls == [*cleanup_plan.commands, ["kill", "-TERM", "4321"]]
    assert result.status == "down"
    assert result.message == "egress brought down"
    assert [phase.name for phase in result.phases] == ["policy_routing_cleanup", "openvpn_stop"]
    assert [phase.status for phase in result.phases] == ["applied", "stopped"]
    assert result.commands_executed == [*[" ".join(command) for command in cleanup_plan.commands], "kill -TERM 4321"]
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
        assert argv[0] == "kill"
        return FakeCommandResult(returncode=0, stdout="stop ok", stderr="")

    result = bring_down_egress(
        cleanup_plan,
        stop_plan,
        cleanup_runner=cleanup_runner,
        stop_runner=stop_runner,
        allow_side_effects=True,
    )

    assert cleanup_calls == cleanup_plan.commands
    assert stop_calls == [["kill", "-TERM", "4321"]]
    assert result.status == "down"
    assert result.commands_executed == [*[" ".join(command) for command in cleanup_plan.commands], "kill -TERM 4321"]


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
    assert result.message == "egress down stopped before OpenVPN stop; routing cleanup failed"
    assert [phase.name for phase in result.phases] == ["policy_routing_cleanup"]
    assert result.commands_executed == [" ".join(cleanup_plan.commands[0])]
    assert result.performed_side_effects is True
