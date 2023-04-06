from django.contrib import messages
from django.contrib.auth.models import User
from django.shortcuts import render

from core.applications.inventory.models import Asset, AssetCategory, AssetSupplier


# Create your views here.
def index(request):
    template = "inventory/index.html"

    context = {
        'assets': Asset.objects.all(),
        'users': list(User.objects.all()),
    }
    return render(request, template, context)


def register(request):
    template = "inventory/register.html"
    if request.method == 'POST':
        # print(request)
        print(request.POST.get('serial'), request.POST.get('tag'))
        asset_payload = {
            "tag": request.POST.get('tag'),
            "purchase_order": request.POST.get('purchase_order'),
            "registration": request.POST.get('registration'),
            "serial": request.POST.get('serial'),
            "purchase_date": request.POST.get('purchase_date'),
            "received_date": request.POST.get('received_date'),
            "brand": request.POST.get('brand'),
            "model": request.POST.get('model'),
            "colour": request.POST.get('colour'),
            "description": request.POST.get('description'),
            "created": "2023-04-01T18:46:56.978154Z",
            "location": "HARARE",
            "shared_resource": False,
            "shared_resource_location": None,
            "condition": None,
            "price": request.POST.get('price'),
            "conversion_rate": request.POST.get('conversion_rate'),
            "category": request.POST.get('category'),
            "current_user": None,
            "allocated_to": None,
            "supplier": None,
            "registered_by": 1
        }
        import requests
        # r = requests.post(url='http://127.0.0.1:8000/softsparks.co.zw/inventory/api/register/', data=asset_payload)
        # messages.success(r.status_code, r.json())
    context = {
        'categories': AssetCategory.objects.all(),
        'users': User.objects.all(),
        'suppliers': AssetSupplier.objects.all(),
    }
    return render(request, template, context)


def asset(request, id):
    template = 'inventory/asset.html'
    asset = None
    try:
        asset = Asset.objects.get(id=id)
    except BaseException as e:
        print(asset)
    context = {
        'asset': asset,
    }
    return render(request, template, context)


def transfer(request):
    template = 'inventory/transfer.html'
    context = {
        'assets': Asset.objects.all(),
        'users': User.objects.all(),
    }
    return render(request, template, context)