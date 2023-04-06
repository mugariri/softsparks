from django.http import JsonResponse
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status

from core.applications.inventory.models import Asset, AssetSupplier, AssetClass, AssetCategory, AssetTransfer
from core.applications.inventory.serializers import AssetSerializer, AssetSupplierSerializer, AssetClassSerializer, \
    AssetCategorySerializer, AssetTransferSerializer


@api_view(['GET', 'POST'])
def asset_register(request):
    if request.method == 'GET':
        asset = Asset.objects.all()
        serializer = AssetSerializer(asset, many=True)
        # return JsonResponse(serializer.data, safe=False)
        return Response(serializer.data)

    elif request.method == 'POST':
        # data = JSONParser().parse(request)
        # serializer = AssetSerializer(data=data)
        serializer = AssetSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            # return JsonResponse(serializer.data, status=201)
            print("Success")
            return Response('success', status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        # return JsonResponse(serializer.errors, status=400)


@api_view(['GET', 'POST', 'PUT', 'DELETE'])
def supplier_register(request):
    if request.method == 'GET':
        supplier = AssetSupplier.objects.all()
        serializer = AssetSupplierSerializer(supplier, many=True)
        # return JsonResponse(serializer.data, safe=False)
        return Response(serializer.data)

    elif request.method == 'POST':
        # data = JSONParser().parse(request)
        # serializer = AssetSerializer(data=data)
        serializer = AssetSupplierSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            # return JsonResponse(serializer.data, status=201)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'POST', 'PUT', 'DELETE'])
def class_register(request):
    if request.method == 'GET':
        asset_class = AssetClass.objects.all()
        serializer = AssetClassSerializer(asset_class, many=True)
        # return JsonResponse(serializer.data, safe=False)
        return Response(serializer.data)

    elif request.method == 'POST':
        # data = JSONParser().parse(request)
        # serializer = AssetSerializer(data=data)
        serializer = AssetClassSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            # return JsonResponse(serializer.data, status=201)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        # return JsonResponse(serializer.errors, status=400)


@api_view(['GET', 'POST', 'PUT', 'DELETE'])
def category_register(request):
    if request.method == 'GET':
        asset_class = AssetCategory.objects.all()
        serializer = AssetCategorySerializer(asset_class, many=True)
        # return JsonResponse(serializer.data, safe=False)
        return Response(serializer.data)

    elif request.method == 'POST':
        # data = JSONParser().parse(request)
        # serializer = AssetSerializer(data=data)
        serializer = AssetCategorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            # return JsonResponse(serializer.data, status=201)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        # return JsonResponse(serializer.errors, status=400)


@api_view(['GET', 'POST'])
def get_tag(request, tag):
    asset = None
    if tag is not None:
        try:
            asset = Asset.objects.get(tag=tag)
            return JsonResponse('exists', safe=False)
        except Asset.DoesNotExist:
            return JsonResponse('not_found', safe=False)
        except BaseException as e:
            JsonResponse(e, safe=False)
    else:
        print("no tag")
        JsonResponse('empty', safe=False)


@api_view(['GET', 'POST'])
def get_serial(request, serial):
    asset = None
    if serial is not None:
        try:
            asset = Asset.objects.get(serial=serial)
            return JsonResponse('exists', safe=False)
        except Asset.DoesNotExist:
            return JsonResponse('not_found', safe=False)
        except BaseException as e:
            JsonResponse(e, safe=False)
    else:
        print("no tag")
        JsonResponse('empty', safe=False)


@api_view(['GET', 'POST'])
def transfer_register(request):
    if request.method == 'GET':
        transfer = AssetTransfer.objects.all()
        serializer = AssetTransferSerializer(transfer, many=True)
        # return JsonResponse(serializer.data, safe=False)
        return Response(serializer.data)

    elif request.method == 'POST':
        # data = JSONParser().parse(request)
        # serializer = AssetSerializer(data=data)
        serializer = AssetTransferSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            # return JsonResponse(serializer.data, status=201)
            print("Success")
            return Response('success', status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        # return JsonResponse(serializer.errors, status=400)
