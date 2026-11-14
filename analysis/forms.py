from django import forms

from analysis.validators import validate_url


class URLAnalysisForm(forms.Form):

    url = forms.CharField(
        label="Enter URL",
        max_length=2048,
        required=True,
        widget=forms.URLInput(
            attrs={
                "placeholder": "https://example.com",
                "class": "url-input",
            }
        ),
    )

    def clean_url(self):
        url = self.cleaned_data["url"]

        try:
            return validate_url(url)
        except ValueError as error:
            raise forms.ValidationError(str(error)) from error