# Common

Source shared by more than one ADR package. Nothing here is installed on its
own.

The Sensor distribution ships both `adr_sensor` and `adr_discovery`, and the
two must not import each other (see Desktop's import contracts), so neither
can own shared code. Each ships a checked-in copy of the shared modules
instead:

| Source | Copies |
|---|---|
| `adr_common/host_identity.py` | `Sensor/adr_sensor/host_identity.py`, `Sensor/adr_discovery/world/host_identity.py` |

Edit the source here, never a copy, then run:

```sh
python Common/sync.py          # rewrite the copies
python Common/sync.py --check  # CI: fail on drift
```

Shared modules must stay standard-library only and Python 3.9 compatible.
