import pytest

# test packages
def test_packages_installed(host):
    for pkg in ["vim", "traceroute", "curl", "wget", "tcpdump", "tree", "net-tools", "bash-completion"]:
        assert host.exists(pkg), f"{pkg} is not be installed"

# test selinux
def test_selinux(host):
    result = host.run("getenforce")
    assert result.rc == 0
    assert result.stdout.strip() in ["Disabled", "Permissive"], "SELinux should be Disabled"

# test firewalld
def test_firewalld(host):
    firewalld = host.service("firewalld")
    assert not firewalld.is_running, "firewalld should not be running"
    assert not firewalld.is_enabled, "firewalld should not be enabled"

# test repo files
def test_epel_repo_enabled(host):
    yum_repos = host.file("/etc/yum.repos.d/epel.repo")
    assert yum_repos.exists, "epel.repo not exist"
    assert yum_repos.contains("enabled=1"), "epel repo should be enabled"

# test chrony.service
def test_chronyd_running_and_enabled(host):
    chronyd = host.service("chronyd")
    assert chronyd.is_running, "chronyd should be running"
    assert chronyd.is_enabled, "chronyd should be enabled"

# test user
def test_user_ops_exists_and_configured(host):
    user = host.user("ops")
    assert user.exists, "User 'ops' should exist"
    assert user.uid >= 1000, "User 'ops' should have normal UID"
    assert user.home == "/home/ops", "User 'ops' should have correct home directory"
    assert user.shell in ["/bin/bash", "/usr/bin/bash"], "User 'ops' should have valid shell"
    assert "wheel" in user.groups, "User 'ops' should be in wheel group for sudo access"

# test ssh
def test_ops_ssh_public_key_exists(host):
    ssh_key = host.file("/sshd/ops_id_rsa.pub")
    assert ssh_key.exists, "/sshd/ops_id_rsa.pub should exist"
    assert ssh_key.size > 0, "SSH public key file should not be empty"
    assert ssh_key.user == "root", "SSH key file should be owned by root"
