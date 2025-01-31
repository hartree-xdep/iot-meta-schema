# XDEP Devices Meta-schema

This repository contains a template meta-schema and the generated meta-schemas for validating the IoT devices schemas in XDEP.

The repository also contains some tests that assert some expectations from the meta-schema as well as test the schemas against it.

## Generating Meta-schemas

To generate a meta-schema for a domain, first add the domain to [`domains.txt`](./domains.txt), then run:

```shell
python -m generate
```

## Running The Tests

To run the tests initialize your python environment by installing the dependencies
from `requirements.txt`, then run:

```shell
python -m tests
```

Tests can also run against a remote dynamodb schema registry but by default this is
disabled.

See `python -m tests --help` to enable remote schema registry tests and for all other options.
