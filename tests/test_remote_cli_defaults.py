from typer.testing import CliRunner

from migate.main import app


def test_remote_acceptance_dry_run_defaults_to_xray_tun_backend_for_first_run_vps_bootstrap():
    result = CliRunner().invoke(app, ["remote", "acceptance"])

    assert result.exit_code == 0
    assert "backend: xray-tun" in result.output
    assert "migate remote egress up --host 166.88.232.2 --port 22 --user root --backend xray-tun --no-dry-run --yes --allow-remote-changes" in result.output
    assert "migate xray tun-service save --yes --allow-system-changes" in result.output
    assert "migate xray apply tun-start --yes --allow-system-changes" in result.output
    assert "migate egress up --no-dry-run --yes --allow-system-changes" not in result.output
