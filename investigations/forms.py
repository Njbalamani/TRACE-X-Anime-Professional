from django import forms

from .models import Investigation


class InvestigationForm(forms.ModelForm):
    class Meta:
        model = Investigation
        fields = ["title", "description"]
        widgets = {
            "title": forms.TextInput(attrs={"class": "input", "placeholder": "e.g. Ransomware activity on FIN-WS-04"}),
            "description": forms.Textarea(
                attrs={"class": "input", "rows": 4, "placeholder": "What is known so far?"}
            ),
        }