from urllib import request
from django.http import JsonResponse
from django.shortcuts import render

# Create your views here.
from rest_framework import generics, permissions
from .serializers import TodoSerializer, TodoToggleCompleteSerializer
from todo.models import Todo

#to sign up
from django.db import IntegrityError
from django.contrib.auth.models import User
from rest_framework.parsers import JSONParser
from rest_framework.authtoken.models import Token
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

#to login
from django.contrib.auth import authenticate

class TodoListCreate(generics.ListCreateAPIView):
    #ListApyView requires two mandatory attributes serializers_class and queryset
    #We specify TodoSerializer which we have earlier implemented 
    serializer_class = TodoSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return Todo.objects.filter(user=user).order_by('-created')

    def perform_create(self, serializer):
        #serializer holds a django model
        serializer.save(user=self.request.user)

class TodoRetrieveUpdateDestroy(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = TodoSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        #user can only update, delete own posts
        return Todo.objects.filter(user=user)

class TodoToggleComplete(generics.UpdateAPIView):
    serializer_class = TodoToggleCompleteSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return Todo.objects.filter(user=user)
    
    def perform_update(self, serializer):
        serializer.instance.completed = not(serializer.instance.completed)
        serializer.save()

@csrf_exempt
def signup(request):
    if request.method == 'POST':
        try:
            data = JSONParser().parse(request) #data is a dictionary
            
            #ToDo validate username and password

            user = User.objects.create(
                username=data['username'],
                password=data['password']
            )
            user.set_password(data['password'])
            user.save()
            token = Token.objects.create(user=user)

            return JsonResponse({'token':str(token)}, status=201)
        except IntegrityError:
            return JsonResponse({'error':'username taken. take another else'}, status=400)

def is_password_accepted(password):
    if (len(password) < 8):
        return True

@csrf_exempt
def login(request):
    if request.method == 'POST':
        data = JSONParser().parse(request)
        user = authenticate(
            request,
            username=data['username'],
            password=data['password'])
        if user is None:
            return JsonResponse(
                {'error':'unable to login. check username and password'},
                status=400)
        else: # return user token
            try:
                token = Token.objects.get(user=user)
            except: # if token not in db, create a new one
                token = Token.objects.create(user=user)
            return JsonResponse({'token':str(token)}, status=201)
