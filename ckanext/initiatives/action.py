# coding: utf8

from __future__ import unicode_literals
import ckan.authz as authz
from ckan.common import _

from ckan.lib.base import render_jinja2
from ckan.lib.mailer import mail_recipient
from ckan.lib.mailer import MailerException
import ckan.logic
from ckan.logic.action.create import user_create
from ckan.logic.action.get import package_search
from ckan.logic.action.get import package_show
from ckan.logic.action.get import resource_search
from ckan.logic.action.get import resource_view_list
from ckan.logic import side_effect_free
from ckanext.initiatives import auth
from ckanext.initiatives import logic
import json

try:
    # CKAN 2.7 and later
    from ckan.common import config
except ImportError:
    # CKAN 2.6 and earlier
    from pylons import config

from logging import getLogger

log = getLogger(__name__)


_get_or_bust = ckan.logic.get_or_bust

NotFound = ckan.logic.NotFound


@side_effect_free
def initiatives_resource_view_list(context, data_dict):
    model = context["model"]
    id = _get_or_bust(data_dict, "id")
    resource = model.Resource.get(id)
    if not resource:
        raise NotFound
    authorized = auth.initiatives_resource_show(
        context, {"id": resource.get("id"), "resource": resource}
    ).get("success", False)
    if not authorized:
        return []
    else:
        return resource_view_list(context, data_dict)


@side_effect_free
def initiatives_package_show(context, data_dict):

    package_metadata = package_show(context, data_dict)

    # Ensure user who can edit can see the resource
    if authz.is_authorized("package_update", context, package_metadata).get(
        "success", False
    ):
        return package_metadata

    # Custom authorization
    if isinstance(package_metadata, dict):
        initiatives_package_metadata = dict(package_metadata)
    else:
        initiatives_package_metadata = dict(package_metadata.for_json())

    # initiatives_package_metadata['resources'] = _initiatives_resource_list_url(
    #     context, initiatives_package_metadata.get('resources', []))
    initiatives_package_metadata["resources"] = _initiatives_resource_list_hide_fields(
        context, initiatives_package_metadata.get("resources", [])
    )

    return initiatives_package_metadata


@side_effect_free
def initiatives_resource_search(context, data_dict):
    resource_search_result = resource_search(context, data_dict)

    initiatives_resource_search_result = {}

    for key, value in resource_search_result.items():
        if key == "results":
            # initiatives_resource_search_result[key] = \
            #     _initiatives_resource_list_url(context, value)
            initiatives_resource_search_result[
                key
            ] = _initiatives_resource_list_hide_fields(context, value)
        else:
            initiatives_resource_search_result[key] = value

    return initiatives_resource_search_result


@side_effect_free
def initiatives_package_search(context, data_dict):
    package_search_result = package_search(context, data_dict)

    initiatives_package_search_result = {}

    for key, value in package_search_result.items():
        if key == "results":
            initiatives_package_search_result_list = []
            for package in value:
                initiatives_package_search_result_list.append(
                    initiatives_package_show(context, {"id": package.get("id")})
                )
            initiatives_package_search_result[
                key
            ] = initiatives_package_search_result_list
        else:
            initiatives_package_search_result[key] = value

    return initiatives_package_search_result


@side_effect_free
def initiatives_check_access(context, data_dict):

    package_id = data_dict.get("package_id", False)
    resource_id = data_dict.get("resource_id", False)

    user_name = logic.initiatives_get_username_from_context(context)

    if not package_id:
        raise ckan.logic.ValidationError("Missing package_id")
    if not resource_id:
        raise ckan.logic.ValidationError("Missing resource_id")

    log.debug("action.initiatives_check_access: user_name = " + str(user_name))

    log.debug("checking package " + str(package_id))
    package_dict = ckan.logic.get_action("package_show")(
        dict(context, return_type="dict"), {"id": package_id}
    )
    log.debug("checking resource")
    resource_dict = ckan.logic.get_action("resource_show")(
        dict(context, return_type="dict"), {"id": resource_id}
    )

    return logic.initiatives_check_user_resource_access(
        user_name, resource_dict, package_dict
    )


def _initiatives_resource_list_hide_fields(context, resource_list):
    initiatives_resources_list = []
    for resource in resource_list:
        # copy original resource
        initiatives_resource = dict(resource)

        # get the restricted fields
        initiatives_dict = logic.initiatives_get_initiatives_dict(initiatives_resource)

        # hide fields to unauthorized users
        authorized = auth.initiatives_resource_show(
            context, {"id": resource.get("id"), "resource": resource}
        ).get("success", False)

        # hide other fields in restricted to everyone but dataset owner(s)
        if not authz.is_authorized(
            "package_update", context, {"id": resource.get("package_id")}
        ).get("success"):

            user_name = logic.initiatives_get_username_from_context(context)

            # hide partially other allowed user_names (keep own)
            allowed_users = []
            for user in initiatives_dict.get("allowed_users"):
                if len(user.strip()) > 0:
                    if user_name == user:
                        allowed_users.append(user_name)
                    else:
                        allowed_users.append(user[0:3] + "*****" + user[-2:])

            new_restricted = json.dumps(
                {
                    "level": initiatives_dict.get("level"),
                    "allowed_users": ",".join(allowed_users),
                }
            )
            extras_restricted = resource.get("extras", {}).get("restricted", {})
            if extras_restricted:
                initiatives_resource["extras"]["restricted"] = new_restricted

            field_initiatives_field = resource.get("restricted", {})
            if field_initiatives_field:
                initiatives_resource["restricted"] = new_restricted

        initiatives_resources_list += [initiatives_resource]
    return initiatives_resources_list
