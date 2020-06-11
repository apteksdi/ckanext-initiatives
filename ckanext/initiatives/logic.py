# coding: utf8

from __future__ import unicode_literals
import ckan.authz as authz
from ckan.common import _

from ckan.lib.base import render_jinja2
import ckan.lib.mailer as mailer
import ckan.logic as logic
import ckan.plugins.toolkit as toolkit
import json
import datetime
import functools

try:
    # CKAN 2.7 and later
    from ckan.common import config
except ImportError:
    # CKAN 2.6 and earlier
    from pylons import config

from logging import getLogger

log = getLogger(__name__)


def get_key_maybe_extras(obj, name):
    # scheming may have put the field on 'extras'
    extras = obj.get("extras", {})
    return obj.get(name, extras.get(name, ""))


def initiatives_get_username_from_context(context):
    auth_user_obj = context.get("auth_user_obj", None)
    user_name = ""
    if auth_user_obj:
        user_name = auth_user_obj.as_dict().get("name", "")
    else:
        if authz.get_user_id_for_username(context.get("user"), allow_none=True):
            user_name = context.get("user", "")
    return user_name


def check_extra_args(nargs):
    def decorator_check_args(fn):
        @functools.wraps(fn)
        def check(u, r, p, *args):
            if len(args) != nargs:
                return {
                    "success": False,
                    "msg": "Resource access restricted to registered users",
                }
            return fn(u, r, p, *args)

        return check

    return decorator_check_args


@check_extra_args(0)
def apply_organization_member(user, resource_dict, package_dict):
    # must be logged in as a registered user
    if not user:
        return {
            "success": False,
            "msg": "Resource access restricted to registered users",
        }

    pkg_organization_id = package_dict.get("owner_org", "")
    # check if the user is a member of this organisation
    for org in logic.get_action("organization_list_for_user")(
        {"user": user}, {"permission": "read"}
    ):
        if org.get("id", "") == pkg_organization_id:
            return {
                "success": True,
            }

    return {
        "success": False,
        "msg": "Resource access restricted to registered users",
    }


@check_extra_args(2)
def apply_access_after(user, resource_dict, package_dict, field_name, days):
    """
    access to resources if the date (YYYY-MM-DD) in `field_name` is
    more than `days` days ago. if not, delegates to `apply_organization_member`
    """

    try:
        days = int(days)
    except ValueError:
        days = None

    dt_str = get_key_maybe_extras(package_dict, field_name)
    try:
        dt = datetime.datetime.strptime(dt_str, "%Y-%m-%d").date()
    except ValueError:
        dt = None
    except TypeError:
        dt = None

    if days is None or dt is None:
        return apply_organization_member(user, resource_dict, package_dict)

    today = datetime.date.today()
    d_days = (today - dt).days

    if d_days >= days:
        return {"success": True}

    return apply_organization_member(user, resource_dict, package_dict)


@check_extra_args(0)
def apply_public(user, resource_dict, package_dict):
    return {
        "success": True,
        "msg": "Resource access restricted to registered users",
    }


PERMISSION_HANDLERS = {
    "public_after_embargo": apply_access_after,
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

    return lambda u, r, p: PERMISSION_HANDLERS[name](u, r, p, *args)


def initiatives_check_user_resource_access(user, resource_dict, package_dict):
    """
    note: calling methods will check if the user has write-access to the enclosing
    package (they are an admin or manager), in which case this method will not be
    called
    """

    resource_permissions = get_key_maybe_extras(package_dict, "resource_permissions")
    permission_handler = parse_resource_permissions(resource_permissions)

    return permission_handler(user, resource_dict, package_dict)
