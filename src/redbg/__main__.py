"""``python -m redbg`` is the same as the ``redbg`` command."""

import sys

from .cli import main

sys.exit(main())
