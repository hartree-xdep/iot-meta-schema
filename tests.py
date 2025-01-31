import unittest
import pathlib
import datetime
import sys
import json
import string
import contextlib
from typing import Iterable

import boto3
from jsonschema import validators, SchemaError
from hypothesis import given
from hypothesis import strategies as st


KNOWN_INVALID_SCHEMAS = [
    'university-of-cambridge/downtime_monitoring/downtime_schema.json',
    'university-of-cambridge/scrap_and_rework_monitoring/block_message.json',
]
"""Schemas that are known to not adhere to the meta schema. These are expected to fail."""

CACHE_DIR_PATH = pathlib.Path('.registry_cache')


def dict_without(value, key):
    """Return a new dict with key removed."""
    result = dict(value)
    result.pop(key)
    return result


def text_st(min_size=0, max_size=None):
    return st.text(alphabet=string.printable, min_size=min_size, max_size=max_size)


def schema(**kwargs):
    return st.builds(dict, **kwargs)


def root_schema(property_schema_st = st.just({})):
    return st.fixed_dictionaries({
        "title": text_st(min_size=5, max_size=60),
        "description": text_st(),
        "$schema": st.just("https://iot.smdh.uk/meta-schema#"),
        "type": st.just("object"),
        "properties": property_schema_st,
    })


INVALID_TYPES = ("object", "boolean", "array", "null")
VALID_TYPES = ("string", "integer", "number")
VALID_MVDTYPES = ("int", "long", "float", "decimal", "bool")


def create_meta_schema_validator():
    with open('meta-schema') as f:
        meta_schema = json.load(f)
    return validators.create(meta_schema)


class BaseTestCase(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.validator = create_meta_schema_validator()
        self.meta_schema = self.validator.META_SCHEMA


class MetaSchemaTestCase(BaseTestCase):
    no_invalid_schemas: bool = False
    """If True, the known invalid schemas will be expected to pass validation instead of failing."""

    def test_meta_schema_is_valid(self):
        meta_schema_validator = validators.validator_for(self.meta_schema)
        meta_schema_validator.check_schema(self.meta_schema)

    BASE_SCHEMA = {
        "title": "Test Schema",
        "description": "test description",
        "$schema": "https://iot.smdh.uk/meta-schema#",
        "type": "object",
        "properties": {},
    }
    TEST_SCHEMAS = [
        [ "schema must not be empty", False, {} ],
        [ "a base schema with no properties is valid", True, BASE_SCHEMA ],
        [ "schema must have a 'title' field", False, dict_without(BASE_SCHEMA, "title") ],
        [ "schema must have a 'description' field", False, dict_without(BASE_SCHEMA, "description") ],
        [ "schema must have a '$schema' field", False, dict_without(BASE_SCHEMA, "$schema") ],
        [ "schema must have a 'type' field", False, dict_without(BASE_SCHEMA, "type") ],
        [ "schema must have a 'properties' field", False, dict_without(BASE_SCHEMA, "properties") ],
        [ "schema 'type' must be 'object'", False, dict_without(BASE_SCHEMA, "properties") ],
        [ "schema title must not exceed 60 characters limit", False, { **BASE_SCHEMA,
            "title": ''.join(string.ascii_letters[i % len(string.ascii_letters)] for i in range(62)),
        } ],
        [ "schema title cannot be empty", False, { **BASE_SCHEMA,
            "title": '',
        } ],
        [ "schema title must be of at least 5 characters", False, { **BASE_SCHEMA,
            "title": ''.join(letter for letter, _ in zip(string.ascii_letters, range(4))),
        } ],
        [ "a base schema with a simple property is valid", True, { **BASE_SCHEMA,
            "properties": {
                "value": { "type": "string" }
            }
        } ],
        [ "a base schema with multiple simple properties is valid", True, { **BASE_SCHEMA,
            "properties": {
                "value": { "type": "integer" },
                "name": { "type": "string" },
                "type": { "type": "string", "enum": ["typeA", "typeB"] }
            }
        } ],
        [ "properties sub-schemas must have a 'type' field", False, { **BASE_SCHEMA,
            "properties": {
                "type": { "enum": ["typeA", "typeB"] }
            }
        } ],
        [ "properties sub-schemas can have an mvDType", True, { **BASE_SCHEMA,
            "properties": {
                "value": {
                    "type": "string",
                    "mvDType": "int",
                }
            }
        } ],
        [ "properties sub-schemas can have an mvDType and must have a type", False, { **BASE_SCHEMA,
            "properties": {
                "value": { "mvDType": "int" }
            }
        } ],
        [ "'mvDType' field accepts int, long, decimal, float, and bool", True, { **BASE_SCHEMA,
            "properties": {
                "value1": { "type": "string", "mvDType": "int" },
                "value2": { "type": "string", "mvDType": "long" },
                "value3": { "type": "string", "mvDType": "float" },
                "value4": { "type": "string", "mvDType": "decimal" },
                "value5": { "type": "string", "mvDType": "bool", "enum": ["0", "1"] },
                "value6": { "type": "string", "mvDType": "bool", "enum": ["1", "0"] },
            }
        } ],
        [ "a bool 'mvDType' field without enum with 0 and 1 strings is invalid", False, { **BASE_SCHEMA,
            "properties": {
                "value": { "type": "string", "mvDType": "bool" },
            }
        } ],
        [ "'mvDType' field requires 'type' to be a string", False, { **BASE_SCHEMA,
            "properties": {
                "value1": { "type": "integer", "mvDType": "int" },
                "value2": { "type": "number", "mvDType": "long" },
                "value3": { "type": "boolean", "mvDType": "float" },
                "value4": { "type": "null", "mvDType": "decimal" },
                "value5": { "type": "object", "mvDType": "bool", "enum": ["0", "1"] },
            }
        } ],
    ]

    def test_meta_schema_expected_validation(self):
        stack = contextlib.ExitStack()
        for msg, valid, schema in self.TEST_SCHEMAS:
            with self.subTest(msg, valid=valid), stack:
                if not valid:
                    stack.enter_context(self.assertRaises(SchemaError))
                self.validator.check_schema(schema)

    @given(schema=root_schema())
    def test_validates_root_schema(self, schema):
        self.validator.check_schema(schema)

    @given(properties_schema=schema(
        value=schema(
            type=st.sampled_from(VALID_TYPES),
    )))
    def test_validates_proper_types(self, properties_schema):
        schema = {**self.BASE_SCHEMA, "properties":properties_schema}
        self.validator.check_schema(schema)

    invalid_type_st = text_st().filter(lambda s: s not in VALID_TYPES)
    invalid_mvdtype_st = text_st().filter(lambda s: s not in VALID_MVDTYPES)

    @given(properties_schema=schema(
        id=st.one_of([
            schema(type=invalid_type_st),
            schema(type=st.just("string"), mvDType=invalid_mvdtype_st),
            schema(type=invalid_type_st, mvDType=invalid_mvdtype_st),
            schema(type=st.sampled_from(INVALID_TYPES)),
            schema(
                type=st.sampled_from(VALID_TYPES).filter(lambda s: s != "string"),
                mvDType=st.sampled_from(VALID_MVDTYPES),
            ),
        ])
    ))
    def test_invalidates_improper_types(self, properties_schema):
        schema = {**self.BASE_SCHEMA, "properties":properties_schema}
        with self.assertRaises(SchemaError):
            self.validator.check_schema(schema)

    def test_devices_schemas_against_meta_schema(self):
        stack = contextlib.ExitStack()
        for schema_path in pathlib.Path().glob('[!.]*/**/*.json'):
            path = str(schema_path)
            with self.subTest(path=path), stack:
                with open(path) as f:
                    schema = json.load(f)
                if path in KNOWN_INVALID_SCHEMAS and not self.no_invalid_schemas:
                    stack.enter_context(self.assertRaises(SchemaError))
                self.validator.check_schema(schema)


class RemoteSchemasTestCase(BaseTestCase):
    schemas: Iterable[dict]
    region: str
    table: str

    id_field = "id"
    schema_field = "jsonSchema"

    @classmethod
    def init(cls, *args):
        cls.region, cls.table = args
        cls.schemas = cls.load_schemas()

    @classmethod
    def load_schemas(cls) -> Iterable[dict]:
        session = boto3.Session()

        cache_content = cls._read_cache_content(session)
        if cache_content is not None:
            yield from json.loads(cache_content)

        schemas = cls._read_remote_schemas(session)
        cls._write_cache_content(json.dumps(schemas), session)
        yield from schemas

    def test_remote_devices_schemas_against_meta_schema(self):
        for obj in self.schemas:
            path, schema = obj["path"], obj["schema"]
            with self.subTest(path=path):
                if isinstance(schema, str):
                    self.fail("invalid JSON document: %s" % schema)
                else:
                    self.validator.check_schema(schema)

    @classmethod
    def _cache_file_path(cls, session: boto3.Session):
        credentials = session.get_credentials()
        assert credentials is not None
        access_key = credentials.access_key
        return (
            CACHE_DIR_PATH / f'remote_schemas_{access_key}_{cls.region}_{cls.table}.json'
        )

    @classmethod
    def _read_cache_content(cls, session: boto3.Session):
        cache_file_path = cls._cache_file_path(session)
        if cache_file_path.exists():
            day_ago = datetime.datetime.now() - datetime.timedelta(days=1)
            if cache_file_path.stat().st_mtime >= day_ago.timestamp():
                return cache_file_path.read_text()
        return None
    
    @classmethod
    def _write_cache_content(cls, content: str, session: boto3.Session):
        cache_file_path = cls._cache_file_path(session)
        cache_file_path.parent.mkdir(parents=True, exist_ok=True)
        cache_file_path.write_text(content)

    @staticmethod
    def _try_load_json(s: str):
        try:
            return json.loads(s), None
        except json.decoder.JSONDecodeError as e:
            return None, e.args[0]

    @classmethod
    def _read_remote_schemas(cls, session: boto3.Session):
        schemas_table = session.resource("dynamodb", region_name=cls.region).Table(cls.table)
     
        schemas: list[dict] = []
        next_page = None
        while True:
            params: dict = {"ExclusiveStartKey": next_page} if next_page is not None else {}
            result = schemas_table.scan(AttributesToGet=[cls.id_field, cls.schema_field], **params)
            next_page = result.get("LastEvaluatedKey")

            items: list[dict] = result["Items"]
            for it in items:
                schema, error = cls._try_load_json(it[cls.schema_field])
                schemas.append({
                    "path": rf"remote://{it[cls.id_field]}",
                    "schema": schema or error,
                })

            if next_page is None:
                break

        return schemas


def remote_arg_type(option):
    try:
        region, table = option.split(":")
        # check that the region resembles an aws region name, e.g. eu-west-1
        part1, part2, part3 = region.split("-")
        if (
            len(part1) != 2
            or part2 not in [
                "north", "east", "south", "west", "central",
                "northeast", "northwest", "southeast", "southwest",
            ] or not part3.isdigit()
        ):
            raise ValueError()
    except:
        raise ValueError('expected remote argument to have a valid format')
    else:
        return region, table


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        '-h',
        '--help',
        action='store_true',
        help='show this help message and exit',
    )
    parser.add_argument(
        '--no-invalid-schemas',
        action='store_true',
        help='run tests on invalid schemas and expect them to pass validation'
    )
    parser.add_argument(
        '--remote',
        default=None,
        type=remote_arg_type,
        metavar='REGIONNAME:TABLENAME',
        help="""
            run tests against a remote dynamodb schema registry.
            WARNING: these tests will scan the complete table
        """,
    )

    options, unknown_args = parser.parse_known_args()
    if options.help:
        parser.print_help()
        print('\nIn addition to the previous options, the following unittest options can be passed:')
        unknown_args.append('-h') # show unittest help
    else:
        if options.remote is None:
            unittest.skip("see --help to run tests on remote schemas")(RemoteSchemasTestCase)
        else:
            RemoteSchemasTestCase.init(*options.remote)

        MetaSchemaTestCase.no_invalid_schemas = options.no_invalid_schemas

    unittest.main(argv=sys.argv[:1] + unknown_args)
