from django.shortcuts import render

from django.shortcuts import HttpResponse
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.decorators import api_view
from rest_framework import status
from .models import *
from rest_framework.views import APIView



# Create your views here.
@api_view(['GET'])
def get_one_place(req: Request, id_place: int):
    place = Place.objects.get(id=id_place)

    json_place = {
        "name": place.name,
        "location": place.location,
        "place type": place.place_type,
        "etoiles": place.etoiles
    }

    return Response(data=json_place, status=200)

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

    def post(self, req: Request):

        print(req.data)
        place = Place()
        place.name = req.data["name"]
        place.location = req.data["location"]
        place.etoiles = req.data["etoiles"]
        place.place_type = req.data["place_type"]

        place.save()
        json_place = {
            "name": place.name,
            "location": place.location,
            "place type": place.place_type,
            "etoiles": place.etoiles
        }
        return Response(data=json_place, status=200)
