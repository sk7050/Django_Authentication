from django.shortcuts import render
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth import authenticate,login,logout
from django.http import HttpResponse
from django.contrib.auth.hashers import check_password
from user_account.models import MyUser
from .forms import UserCreationForm
import re 



def email_check(mail):
      emaillist = list()
      detail=MyUser.objects.order_by("name")
      for i in detail:
        emaillist.append(str(i.email))

      if mail in emaillist:
           error="Already Exist this mail"
           return error
      else:
         error=0
         return error

def phone_check(phone):
      phonellist = list()
      detail=MyUser.objects.order_by("name")
      for i in detail:
        phonellist.append(str(i.phone))

      if phone in phonellist:
           error="Already Exist this phone number"
           return error
      else:
         error=0
         return error
def pass_check(psw1,psw2):
      if psw1 != psw2:
          error='Passwords are not same'
          return error
      elif len(psw1)<=6:
          error="Password's lenth should be grater then 6 digit"
          return error
      elif not re.search("[a-z]", psw1 ) or not re.search("[A-Z]", psw1 ) or not re.search("[0-9]", psw1 ) :
          error=''' The alphabets must be between [a-z]
                    At least one alphabet should be of Upper Case [A-Z]
                    At least 1 number or digit between [0-9].
                  '''
          return error
      else:
          error=0
          return error


        

def clean_password(password1,email):
        # Check that the two password entries match
        if email=='':
            error="Please  input your mail "
        elif password1=='':
            error="Please give your password "
        else:
            u = MyUser.objects.get(email=email)
            password2=u.password
            print(password2)
            if password1 and password2 and password1 != password2:
                error="password incorrect or email not found please try again"

        

        return error

# Create your views here.
def login_user(request):
    if request.method == "POST":
        email = request.POST['email']
        password = request.POST['password']
        
        user = authenticate(request, email=email, password=password)
        if user is not None:
            login(request, user)
            messages.success(request,"You have login")
            return HttpResponse('<h1>You have login</h1>')

        else:
            error=clean_password(request.POST['password'],request.POST['email'])
            print(error)
            messages.error(request,error)
            return render(request,'login.html')

    else:
        return render(request,'login.html')

def signup_user(request):
    
    form=UserCreationForm
    
    context={'form':form}
    if  request.method == "POST":
        email = request.POST['email']
        phone=  request.POST['phone']
        password1 = request.POST['password1']
        password2 = request.POST['password2']
        error=pass_check(password1,password2)
        print(error)
        messages.error(request,error)
        if error == 0:
            data=form(request.POST)
            try:
                if data.is_valid:
                    data.save()
                    return render(request,'login.html')
            except:
                error=email_check(email) or phone_check(phone)
                messages.error(request,error)
    
    return render(request,'signup.html',context)
    
