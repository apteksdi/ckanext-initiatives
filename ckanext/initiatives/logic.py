# coding: utf8

from __future__ import unicode_literals
import ckan.authz as authz
from ckan.common import _

from ckan.lib.base import render_jinja2
import ckan.lib.mailer as mailer
import ckan.logic as logic
import ckan.plugins.toolkit as toolkit
import json
import functools

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


def check_args(nargs):
    def decorator_check_args(fn):
        @functools.wraps(fn)
        def check(*args):
            if len(args) != nargs:
                return {
                    "success": False,
                    "msg": "Resource access restricted to registered users",
                }
        return check
    return decorator_check_args


@check_args(2)
def apply_access_after(field_name, days):
    return {
        "success": False,
        "msg": "Resource access restricted to registered users",
    }


@check_args(0)
def apply_organization_member():
    return {
        "success": False,
        "msg": "Resource access restricted to registered users",
    }


@check_args(0)
def apply_public():
    return {
        "success": True,
        "msg": "Resource access restricted to registered users",
    }


PERMISSION_HANDLERS = {
    "access_after": apply_access_after,
    "organization_member": apply_organization_member,
    "public": apply_public,
}


def parse_resource_permissions(permission_str):
    """
    syntax is:
    handler_name:arg1:arg2
    """
    parts = [t.strip() for t in permission_str.split(":")]
    if len(parts) > 0:
        name, args = parts[0], parts[1:]
    else:
        name = ""
        args = []
    # a safe, restrictive default: we never seek to restrict
    # data beyond organization members
    if name not in PERMISSION_HANDLERS:
        name = "organization_member"
    return lambda: PERMISSION_HANDLERS[name](args)


def initiatives_check_user_resource_access(user, resource_dict, package_dict):
    """
    note: calling methods will check if the user has write-access to the enclosing
    package (they are an admin or manager), in which case this method will not be
    called
    """

    permission_handler = parse_resource_permissions(
        package_dict.get("resource_permissions", "")
    )

    return permission_handler()

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
