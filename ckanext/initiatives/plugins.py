
import logging
import ckan.plugins as plugins
from ckanext.initiatives import action, auth, helpers



log = logging.getLogger(__name__)


class InitiativesPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IActions)
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IAuthFunctions)
    plugins.implements(plugins.ITemplateHelpers)

    # IConfigurer
    def update_config(self, config):
        plugins.toolkit.add_template_directory(config, "templates")
        plugins.toolkit.add_public_directory(config, "static")

    # IAuthFunctions
    def get_auth_functions(self):
        return {'resource_show': auth.initiatives_resource_show,
                'resource_view_show': auth.initiatives_resource_show}

    # IActions
    def get_actions(self):
        return {'resource_view_list': action.initiatives_resource_view_list,
                'initiatives_check_access': action.initiatives_check_access }

    # ITemplateHelpers
    def get_helpers(self):
        return {"initiatives_get_user_id": helpers.initiatives_get_user_id}
 