import yaml

API_TOKEN = "dummy-token-for-tests-only"


def load_config(stream):
    return yaml.load(stream)
