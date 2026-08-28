class AuthorForm(forms.ModelForm):
    class Meta:
        model = Author
        fields = ["name"]


class EditorForm(forms.ModelForm):
    class Meta:
        model = Editor
        exclude = ["id"]
