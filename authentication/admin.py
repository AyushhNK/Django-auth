from django.contrib import admin
from .models import User, VerificationToken

# Register your models here.
admin.site.register(User)
admin.site.register(VerificationToken)
