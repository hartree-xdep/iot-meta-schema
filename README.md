# XDEP Devices Meta-schema

This repository contains the meta-schema for validating the IoT devices schemas. The repository also contains some tests
that assert some expectations from the meta-schema as well as test the schemas against it.

## Running the tests

To run the tests initialize your python environment by installing the dependencies
from `requirements.txt`, then run:

```shell
python -m tests
```

Tests can also run against a remote dynamodb schema registry but by default this is
disabled.

See `python -m tests --help` to enable remote schema registry tests and for all other options.
