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
def initiatives_check_access(context, data_dict):

    package_id = data_dict.get("package_id", False)
    resource_id = data_dict.get("resource_id", False)

    user_name = logic.initiatives_get_username_from_context(context)

    if not package_id:
        raise ckan.logic.ValidationError("Missing package_id")
    if not resource_id:
        raise ckan.logic.ValidationError("Missing resource_id")

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

