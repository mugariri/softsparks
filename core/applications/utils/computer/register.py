import subprocess as sb
from threading import Thread
from time import sleep
import requests

data = None
import time

serial = sb.getoutput("wmic bios get serialnumber").split('\n')[2].rstrip()


def processor_info():
    import subprocess as sb
    info = sb.getoutput('wmic cpu get name')
    return info.split('\n')[2]


def get_ip():
    import socket
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    return str(ip)


output = sb.getoutput("systeminfo")
username = sb.getoutput("whoami").split("\\")[1]
hostname = output.split("\n")[1].split(":")[1].strip()
product_id = output.split("\n")[9].split(":")[1].strip()
manufacturer = output.split("\n")[12].split(":")[1].strip()
model = output.split("\n")[13].split(":")[1].strip()
date_manufactured = output.split("\n")[17].split(":")[1].strip().split(",")[1].strip()
ram = output.split("\n")[24].split(":")[1]
import shutil

path = "C:"
stat = shutil.disk_usage(path)
disk_size = list(stat)
