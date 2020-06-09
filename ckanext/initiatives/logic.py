# coding: utf8

from __future__ import unicode_literals
import ckan.authz as authz
from ckan.common import _

from ckan.lib.base import render_jinja2
import ckan.lib.mailer as mailer
import ckan.logic as logic
import ckan.plugins.toolkit as toolkit
import json

try:
    # CKAN 2.7 and later
    from ckan.common import config
except ImportError:
    # CKAN 2.6 and earlier
    from pylons import config

from logging import getLogger

log = getLogger(__name__)


def initiatives_get_username_from_context(context):
    auth_user_obj = context.get("auth_user_obj", None)
    user_name = ""
    if auth_user_obj:
        user_name = auth_user_obj.as_dict().get("name", "")
    else:
        if authz.get_user_id_for_username(context.get("user"), allow_none=True):
            user_name = context.get("user", "")
    return user_name


def initiatives_get_initiatives_dict(resource_dict):
    initiatives_dict = {"level": "public", "allowed_users": []}

    # the ckan plugins ckanext-scheming and ckanext-composite
    # change the structure of the resource dict and the nature of how
    # to access our restricted field values
    if resource_dict:
        # the dict might exist as a child inside the extras dict
        extras = resource_dict.get("extras", {})
        # or the dict might exist as a direct descendant of the resource dict
        restricted = resource_dict.get("restricted", extras.get("restricted", {}))
        if not isinstance(restricted, dict):
            # if the restricted property does exist, but not as a dict,
            # we may need to parse it as a JSON string to gain access to the values.
            # as is the case when making composite fields
            try:
                restricted = json.loads(restricted)
            except ValueError:
                restricted = {}

        if restricted:
            initiatives_level = restricted.get("level", "public")
            allowed_users = restricted.get("allowed_users", "")
            if not isinstance(allowed_users, list):
                allowed_users = allowed_users.split(",")
            initiatives_dict = {
                "level": initiatives_level,
                "allowed_users": allowed_users,
            }

    return initiatives_dict


def initiatives_check_user_resource_access(user, resource_dict, package_dict):

    initiatives_dict = initiatives_get_initiatives_dict(resource_dict)

    initiatives_level = initiatives_dict.get("level", "public")
    allowed_users = initiatives_dict.get("allowed_users", [])

    # Public resources (DEFAULT)
    if not initiatives_level or initiatives_level == "public":
        return {"success": True}

    # Registered user
    if not user:
        return {
            "success": False,
            "msg": "Resource access restricted to registered users",
        }
    else:
        if initiatives_level == "registered" or not initiatives_level:
            return {"success": True}

    # Since we have a user, check if it is in the allowed list
    if user in allowed_users:
        return {"success": True}
    elif initiatives_level == "only_allowed_users":
        return {
            "success": False,
            "msg": "Resource access restricted to allowed users only",
        }

    # Get organization list
    user_organization_dict = {}

    context = {"user": user}
    data_dict = {"permission": "read"}

    for org in logic.get_action("organization_list_for_user")(context, data_dict):
        name = org.get("name", "")
        id = org.get("id", "")
        if name and id:
            user_organization_dict[id] = name

    # Any Organization Members (Trusted Users)
    if not user_organization_dict:
        return {
            "success": False,
            "msg": "Resource access restricted to members of an organization",
        }

    if initiatives_level == "any_organization":
        return {"success": True}

    pkg_organization_id = package_dict.get("owner_org", "")

    # Same Organization Members
    if initiatives_level == "same_organization":
        if pkg_organization_id in user_organization_dict.keys():
            return {"success": True}

    return {
        "success": False,
        "msg": (
            "Resource access restricted to same " "organization ({}) members"
        ).format(pkg_organization_id),
    }
