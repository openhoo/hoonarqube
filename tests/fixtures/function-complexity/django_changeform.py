# Pinned regression for issue #671. Source: django/django
# Commit: 8cbdd4a814397f81adf0129288f32b615bd1f94f
# django/contrib/admin/options.py:2068-2246, dedented; otherwise unchanged.
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

def _changeform_view(self, request, object_id, form_url, extra_context):
    to_field = request.POST.get(TO_FIELD_VAR, request.GET.get(TO_FIELD_VAR))
    if to_field and not self.to_field_allowed(request, to_field):
        raise DisallowedModelAdminToField(
            "The field %s cannot be referenced." % to_field
        )

    if request.method == "POST" and "_saveasnew" in request.POST:
        object_id = None

    add = object_id is None

    if add:
        if not self.has_add_permission(request):
            raise PermissionDenied
        obj = None

    else:
        obj = self.get_object(request, unquote(object_id), to_field)
        if not self.has_view_or_change_permission(request, obj):
            raise PermissionDenied

        if obj is None:
            return self._get_obj_does_not_exist_redirect(
                request, self.opts, object_id
            )

    action_form = None
    # RemovedInDjango2028Warning: When the deprecation ends, replace with:
    # actions = self.get_actions(
    #     request, action_location=ActionLocation.CHANGE_FORM
    # )
    actions = self._get_actions_with_action_location(
        request, action_location=ActionLocation.CHANGE_FORM
    )
    if actions and not add:
        action_location = ActionLocation.CHANGE_FORM
        action_form = self.action_form(auto_id=None, prefix=action_location.value)
        # RemovedInDjango2028Warning: When the deprecation ends, replace:
        # action_form.fields["action"].choices = self.get_action_choices(
        #     request, action_location=action_location
        # )
        action_form.fields["action"].choices = (
            self._get_action_choices_with_action_location(
                request, action_location=action_location
            )
        )
    fieldsets = self.get_fieldsets(request, obj)
    ModelForm = self.get_form(
        request, obj, change=not add, fields=flatten_fieldsets(fieldsets)
    )
    if request.method == "POST":
        if (
            action_form
            and action_form["action"].html_name in request.POST
            and "_save" not in request.POST
            and "_continue" not in request.POST
            and "_addanother" not in request.POST
        ):
            selected = request.POST.getlist(helpers.ACTION_CHECKBOX_NAME)
            if len(selected) != 1 or selected[0] != str(obj.pk):
                raise BadRequest
            queryset = self.get_queryset(request)
            if response := self.response_action(
                request, queryset, action_location=ActionLocation.CHANGE_FORM
            ):
                return response
            return HttpResponseRedirect(request.get_full_path())

        if not add and not self.has_change_permission(request, obj):
            raise PermissionDenied

        form = ModelForm(request.POST, request.FILES, instance=obj)
        formsets, inline_instances = self._create_formsets(
            request,
            form.instance,
            change=not add,
        )
        form_validated = form.is_valid()
        if form_validated:
            new_object = self.save_form(request, form, change=not add)
        else:
            new_object = form.instance
        if all_valid(formsets) and form_validated:
            self.save_model(request, new_object, form, not add)
            self.save_related(request, form, formsets, not add)
            change_message = self.construct_change_message(
                request, form, formsets, add
            )
            if add:
                self.log_addition(request, new_object, change_message)
                return self.response_add(request, new_object)
            else:
                self.log_change(request, new_object, change_message)
                return self.response_change(request, new_object)
        else:
            form_validated = False
    else:
        if add:
            initial = self.get_changeform_initial_data(request)
            form = ModelForm(initial=initial)
            formsets, inline_instances = self._create_formsets(
                request, form.instance, change=False
            )
        else:
            form = ModelForm(instance=obj)
            formsets, inline_instances = self._create_formsets(
                request, obj, change=True
            )

    if not add and not self.has_change_permission(request, obj):
        readonly_fields = flatten_fieldsets(fieldsets)
    else:
        readonly_fields = self.get_readonly_fields(request, obj)
    admin_form = helpers.AdminForm(
        form,
        list(fieldsets),
        # Clear prepopulated fields on a view-only form to avoid a crash.
        (
            self.get_prepopulated_fields(request, obj)
            if add or self.has_change_permission(request, obj)
            else {}
        ),
        readonly_fields,
        model_admin=self,
    )
    media = self.media + admin_form.media

    inline_formsets = self.get_inline_formsets(
        request, formsets, inline_instances, obj
    )
    for inline_formset in inline_formsets:
        media += inline_formset.media
    if action_form:
        media += action_form.media

    if add:
        title = _("Add %s")
    elif self.has_change_permission(request, obj):
        title = _("Change %s")
    else:
        title = _("View %s")
    context = {
        **self.admin_site.each_context(request),
        "title": title % self.opts.verbose_name,
        "subtitle": (
            display_for_value(str(obj), EMPTY_VALUE_STRING) if obj else None
        ),
        "adminform": admin_form,
        "object_id": object_id,
        "original": obj,
        "is_popup": IS_POPUP_VAR in request.POST or IS_POPUP_VAR in request.GET,
        "source_model": request.GET.get(SOURCE_MODEL_VAR),
        "to_field": to_field,
        "media": media,
        "action_form": action_form,
        "action_checkbox_name": helpers.ACTION_CHECKBOX_NAME,
        "inline_admin_formsets": inline_formsets,
        "errors": helpers.AdminErrorList(form, formsets),
        "preserved_filters": self.get_preserved_filters(request),
    }

    # Hide the "Save" and "Save and continue" buttons if "Save as New" was
    # previously chosen to prevent the interface from getting confusing.
    if (
        request.method == "POST"
        and not form_validated
        and "_saveasnew" in request.POST
    ):
        context["show_save"] = False
        context["show_save_and_continue"] = False
        # Use the change template instead of the add template.
        add = False

    context.update(extra_context or {})

    return self.render_change_form(
        request, context, add=add, change=not add, obj=obj, form_url=form_url
    )
