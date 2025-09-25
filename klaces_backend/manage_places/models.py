from django.db import models

# Create your models here.

class Place(models.Model):
    TYPE_CHOICE: list = [
        ("restaurant", "RESTAURANT"),
        ("fast_food", "FAST FOOD")
    ]

    location = models.CharField(max_length=100)
    name = models.CharField(max_length=50)
    place_type = models.CharField(max_length=20, choices=TYPE_CHOICE, default="restaurant")
    etoiles = models.FloatField(default=0.0)
