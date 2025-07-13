# Sandproxy

An experimental SSH-based residential proxy orchestrator for use with [Sandhole](https://github.com/EpicEric/sandhole).

## Status

Currently a work-in-progress.

## Usage

From the proxy orchestrator side:

```bash
docker run -v ./data:/data:ro epiceric/sandproxy:latest -c /data/config.toml
```

From the residential proxy side:

```bash
docker run -v id_ed25519:/root/.ssh/id_ed25519:ro -v sandproxy_key.pub:/root/.ssh/authorized_keys:ro epiceric/sandproxy-client:latest autossh -M 0 -i /root/.ssh/id_ed25519 -R my-ssh-host:22:localhost:22 sandhole.com.br
```
