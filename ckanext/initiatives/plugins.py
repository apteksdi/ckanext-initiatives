
import logging
from ckan.plugins import toolkit, IConfigurer, IRoutes, SingletonPlugin, implements


log = logging.getLogger(__name__)


class InitiativesPlugin(SingletonPlugin):
    implements(IConfigurer)
    implements(IRoutes, inherit=True)

    def update_config(self, config):
        toolkit.add_template_directory(config, "templates")
        toolkit.add_public_directory(config, "static")

