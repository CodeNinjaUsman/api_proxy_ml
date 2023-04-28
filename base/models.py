from django.db import models

class Sentence(models.Model):
    input = models.CharField(max_length=25500)
    label = models.CharField(max_length=255)
    score = models.FloatField()

