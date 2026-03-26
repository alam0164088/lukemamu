from django.shortcuts import render

def home(request):
    return render(request, "home.html")

def custom_404(request, exception):
    """Custom 404 error handler"""
    return render(request, "404.html", {"request": request}, status=404)