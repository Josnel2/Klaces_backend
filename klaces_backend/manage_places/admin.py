from django.contrib import admin
from .models import Place


class Place_register(admin.ModelAdmin):
    list_display = ["id", "location", "place_type", "etoiles"]

# Register your models here.

admin.site.register(Place, Place_register)
