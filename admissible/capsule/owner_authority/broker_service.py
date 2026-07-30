"""Entry point for the privileged owner-authority broker service.

The systemd unit written by the installer starts exactly this module.  It
attests the fixed production installation, binds the fixed socket and serves
the closed protocol.  It accepts no path, key or state arguments.
"""

from __future__ import annotations

import sys
from typing import Sequence

from admissible.capsule.owner_authority.broker import OwnerAuthorityBroker
from admissible.capsule.owner_authority.installation import (
    attest_production_installation,
)
from admissible.capsule.owner_authority.layout import OwnerAuthorityError


def main(argv: Sequence[str] | None = None) -> int:
    if argv:
        print(
            "refusing: the owner-authority broker takes no arguments",
            file=sys.stderr,
        )
        return 2
    try:
        broker = OwnerAuthorityBroker(attest_production_installation())
    except OwnerAuthorityError as error:
        print(f"{error}", file=sys.stderr)
        return 1
    try:
        broker.bind()
        broker.serve_forever()
    except OwnerAuthorityError as error:
        print(f"{error}", file=sys.stderr)
        return 1
    finally:
        broker.close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
