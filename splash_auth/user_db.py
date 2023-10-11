from dataclasses import dataclass
from typing import Dict, List

import yaml


@dataclass
class Users:
    users: List[str]
    api_keys: List[str]


def populate_users():
    users = Users([], [])
    with open("/app/users.yml", "r") as users_file:
        users.users = yaml.safe_load(users_file)["users"]

    with open("/app/api_keys.yml", "r") as api_keys_file:
        users.api_keys = yaml.safe_load(api_keys_file)["valid_keys"]
    return users


users_db = populate_users()
