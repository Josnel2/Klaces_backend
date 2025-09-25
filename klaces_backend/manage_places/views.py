from django.shortcuts import render

from django.shortcuts import HttpResponse
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework import status
from .models import *
from rest_framework.views import APIView



# Create your views here.


class Api_place(APIView):

    def get(self, request: Request):

       try:
           place = Place.objects.get(id=request.data["id"])
           return Response(data=place, status=status.HTTP_200_OK)
       except KeyError:
           places = Place.objects.all()
           data = []
           for elt in places:
               meta = {
                   "name": elt.name,
                   "location": elt.location,
                   "place type": elt.place_type,
                   "etoiles": elt.etoiles
               }

               data.append(meta)

           return Response(data=data, status=status.HTTP_200_OK)