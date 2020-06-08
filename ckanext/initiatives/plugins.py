
import logging
import ckan.plugins as plugins
from ckanext.initiatives import action, auth



log = logging.getLogger(__name__)


class InitiativesPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IActions)
    plugins.implements(plugins.IAuthFunctions)

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
                'package_show': action.initiatives_package_show,
                'resource_search': action.initiatives_resource_search,
                'package_search': action.initiatives_package_search,
                'initiatives_check_access': action.initiatives_check_access }
