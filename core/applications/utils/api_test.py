from core.applications.utils.computer.register import processor_info, serial, get_ip, manufacturer, model, disk_size, \
    ram

asset_payload = {
    "tag": serial,
    "purchase_order": None,
    "registration": None,
    "serial": serial,
    "purchase_date": "2023-04-01T20:43:19Z",
    "received_date": "2023-04-01T20:43:19Z",
    "brand": manufacturer,
    "model": model,
    "colour": "Black",
    "description": "",
    "ram": ram,
    "ip_address": get_ip(),
    "disk_size": disk_size,
    "processor": processor_info(),
    "created": "2023-04-01T18:46:56.978154Z",
    "location": "HARARE",
    "shared_resource": False,
    "shared_resource_location": None,
    "condition": None,
    "price": None,
    "conversion_rate": None,
    "category": 1,
    "current_user": None,
    "allocated_to": None,
    "supplier": None,
    "registered_by": 1
}

import requests

r = requests.post(url="http://127.0.0.1:8000/softsparks.co.zw/inventory/api/register/", data=asset_payload)
print(r.status_code)
