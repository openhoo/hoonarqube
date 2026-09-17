# Pinned regression for issue #671. Source: django/django
# Commit: 8cbdd4a814397f81adf0129288f32b615bd1f94f
# django/apps/config.py:99-222, dedented; otherwise unchanged.
# Copyright (c) Django Software Foundation and individual contributors.
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
# 
#     1. Redistributions of source code must retain the above copyright notice,
#        this list of conditions and the following disclaimer.
# 
#     2. Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
# 
#     3. Neither the name of Django nor the names of its contributors may be used
#        to endorse or promote products derived from this software without
#        specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

@classmethod
def create(cls, entry):
    """
    Factory that creates an app config from an entry in INSTALLED_APPS.
    """
    # create() eventually returns app_config_class(app_name, app_module).
    app_config_class = None
    app_name = None
    app_module = None

    # If import_module succeeds, entry points to the app module.
    try:
        app_module = import_module(entry)
    except Exception:
        pass
    else:
        # If app_module has an apps submodule that defines a single
        # AppConfig subclass, use it automatically.
        # To prevent this, an AppConfig subclass can declare a class
        # variable default = False.
        # If the apps module defines more than one AppConfig subclass,
        # the default one can declare default = True.
        if module_has_submodule(app_module, APPS_MODULE_NAME):
            mod_path = "%s.%s" % (entry, APPS_MODULE_NAME)
            mod = import_module(mod_path)
            # Check if there's exactly one AppConfig candidate,
            # excluding those that explicitly define default = False.
            app_configs = [
                (name, candidate)
                for name, candidate in inspect.getmembers(mod, inspect.isclass)
                if (
                    issubclass(candidate, cls)
                    and candidate is not cls
                    and getattr(candidate, "default", True)
                )
            ]
            if len(app_configs) == 1:
                app_config_class = app_configs[0][1]
            else:
                # Check if there's exactly one AppConfig subclass,
                # among those that explicitly define default = True.
                app_configs = [
                    (name, candidate)
                    for name, candidate in app_configs
                    if getattr(candidate, "default", False)
                ]
                if len(app_configs) > 1:
                    candidates = [repr(name) for name, _ in app_configs]
                    raise RuntimeError(
                        "%r declares more than one default AppConfig: "
                        "%s." % (mod_path, ", ".join(candidates))
                    )
                elif len(app_configs) == 1:
                    app_config_class = app_configs[0][1]

        # Use the default app config class if we didn't find anything.
        if app_config_class is None:
            app_config_class = cls
            app_name = entry

    # If import_string succeeds, entry is an app config class.
    if app_config_class is None:
        try:
            app_config_class = import_string(entry)
        except Exception:
            pass
    # If both import_module and import_string failed, it means that entry
    # doesn't have a valid value.
    if app_module is None and app_config_class is None:
        # If the last component of entry starts with an uppercase letter,
        # then it was likely intended to be an app config class; if not,
        # an app module. Provide a nice error message in both cases.
        mod_path, _, cls_name = entry.rpartition(".")
        if mod_path and cls_name[0].isupper():
            # We could simply re-trigger the string import exception, but
            # we're going the extra mile and providing a better error
            # message for typos in INSTALLED_APPS.
            # This may raise ImportError, which is the best exception
            # possible if the module at mod_path cannot be imported.
            mod = import_module(mod_path)
            candidates = [
                repr(name)
                for name, candidate in inspect.getmembers(mod, inspect.isclass)
                if issubclass(candidate, cls) and candidate is not cls
            ]
            msg = "Module '%s' does not contain a '%s' class." % (
                mod_path,
                cls_name,
            )
            if candidates:
                msg += " Choices are: %s." % ", ".join(candidates)
            raise ImportError(msg)
        else:
            # Re-trigger the module import exception.
            import_module(entry)

    # Check for obvious errors. (This check prevents duck typing, but
    # it could be removed if it became a problem in practice.)
    if not issubclass(app_config_class, AppConfig):
        raise ImproperlyConfigured("'%s' isn't a subclass of AppConfig." % entry)

    # Obtain app name here rather than in AppClass.__init__ to keep
    # all error checking for entries in INSTALLED_APPS in one place.
    if app_name is None:
        try:
            app_name = app_config_class.name
        except AttributeError:
            raise ImproperlyConfigured("'%s' must supply a name attribute." % entry)

    # Ensure app_name points to a valid module.
    try:
        app_module = import_module(app_name)
    except ImportError:
        raise ImproperlyConfigured(
            "Cannot import '%s'. Check that '%s.%s.name' is correct."
            % (
                app_name,
                app_config_class.__module__,
                app_config_class.__qualname__,
            )
        )

    # Entry is a path to an app config class.
    return app_config_class(app_name, app_module)
