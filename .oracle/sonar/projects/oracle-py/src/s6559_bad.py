class BookForm(forms.ModelForm):
    class Meta:
        model = Book


class PlainForm(ModelForm):
    pass
