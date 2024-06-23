from django import forms
from .models import Purpose, Mapping, ProjectEffort

class PurposeAdminForm(forms.ModelForm):
    class Meta:
        model = Purpose
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super(PurposeAdminForm, self).__init__(*args, **kwargs)
        self.fields['desired_outcomes'].queryset = Mapping.objects.filter(type='OUT')

class ProjectEffortAdminForm(forms.ModelForm):
    class Meta:
        model = ProjectEffort
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super(ProjectEffortAdminForm, self).__init__(*args, **kwargs)
        self.fields['outcome'].queryset = Mapping.objects.filter(type='OUT')