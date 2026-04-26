# MiniSnort (Sprint 0)

Sprint 0 provides a minimal Docker lab and C++ skeleton that builds a `minisnort` binary with DAQ placeholders (`pcap` and `nfqueue`).

## Quick start

```bash
./scripts/lab_up.sh
```

Open attacker shell:

```bash
docker exec -it ms_attacker bash
```

Run lab down:

```bash
./scripts/lab_down.sh
```

## Verification helpers

This repo also includes evidence capture helpers:

- `scripts/verify_capture.sh`
- `scripts/tail_evidence.sh`

Evidence outputs are written under `logs/evidence/<sprint>/`.
