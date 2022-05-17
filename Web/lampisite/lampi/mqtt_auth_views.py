from django.http import HttpResponse, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate
from django.contrib.sessions.models import Session
from django.contrib.auth.models import User
from paho.mqtt.client import topic_matches_sub
from . import models


ACL_READ = "1"
ACL_WRITE = "2"
ACL_SUBSCRIBE = "4"


def unpack_POST_data(req):
    post_data = req.POST

    username = post_data.get("username", "")
    password = post_data.get("password", "")
    topic = post_data.get("topic", "")
    acc = post_data.get("acc", "")
    clientid = post_data.get("clientid", "")

    print("  UNPACKED POST: U: '{}' P: '{}'"
          " T: '{}' A: '{}' C: '{}'".format(username,
                                            password,
                                            topic,
                                            acc,
                                            clientid))

    return username, password, topic, acc, clientid


def get_user_from_session_key(session_key):
    try:
        session = Session.objects.get(session_key=session_key)
    except Session.DoesNotExist:
        return None
    uid = session.get_decoded().get('_auth_user_id')
    try:
        return User.objects.get(pk=uid)
    except User.DoesNotExist:
        return None


DEVICE_BRIDGE_READ_TOPIC_LIST = [
  "devices/{}/lamp/set_config",
  "devices/{}/lamp/associated",
]

DEVICE_BRIDGE_WRITE_TOPIC_LIST = [
  "$SYS/broker/connection/{}_broker/state",
  "devices/{}/lamp/connection/lamp_service/state",
  "devices/{}/lamp/connection/lamp_ui/state",
  "devices/{}/lamp/connection/lamp_bt_peripheral/state",
  "devices/{}/lamp/connection/bluetooth/state",
  "devices/{}/lamp/changed",
]


def get_acls_for_bridge(device_id):
    read_list, write_list = [], []
    for t in DEVICE_BRIDGE_READ_TOPIC_LIST:
        read_list.append(t.format(device_id))
    for t in DEVICE_BRIDGE_WRITE_TOPIC_LIST:
        write_list.append(t.format(device_id))
    return read_list, write_list


USER_READ_TOPIC_LIST = [
  "$SYS/broker/connection/{}_broker/state",
  "devices/{}/lamp/connection/lamp_service/state",
  "devices/{}/lamp/connection/lamp_ui/state",
  "devices/{}/lamp/connection/lamp_bt_peripheral/state",
  "devices/{}/lamp/connection/bluetooth/state",
  "devices/{}/lamp/changed",
]

USER_WRITE_TOPIC_LIST = [
  "devices/{}/lamp/set_config",
]


def get_acls_for_user(user):
    # a non-superuser should only have access to their devices
    read_list, write_list = [], []
    for lamp in user.lampi_set.all():
        device_id = lamp.device_id
        for t in USER_READ_TOPIC_LIST:
            read_list.append(t.format(device_id))
        for t in USER_WRITE_TOPIC_LIST:
            write_list.append(t.format(device_id))
    return read_list, write_list


@csrf_exempt
def auth(req):
    if req.method == 'POST':
        if req.META['REMOTE_ADDR'] == '127.0.0.1':
            username, password, topic, acc, clientid = unpack_POST_data(req)
            # need to handle
            #   django users - with username and password (mqtt-daemon)
            #   django users - with websockets
            #      username: device_id
            #      password: django session_key
            #   LAMPI devices - brokers authenticated with Certificates
            #      mosquitto handles SSL/TLS auth directly, so this
            #      auth function never is invoked
            #
            # try Django username and password
            user = authenticate(username=username, password=password)
            if user is not None:
                return HttpResponse(None, content_type='application/json')

            # try django websockets
            #  username is device id
            #  password is django session key of user that owns device
            user = get_user_from_session_key(password)
            if user:
                try:
                    device = models.Lampi.objects.get(device_id=username,
                                                      user=user)
                    return HttpResponse(None, content_type='application/json')
                except models.Lampi.DoesNotExist:
                    pass
    return HttpResponseForbidden(None, content_type='application/json')


@csrf_exempt
def superuser(req):
    # do not allow any superusers
    return HttpResponseForbidden(None, content_type='application/json')


@csrf_exempt
def acl(req):
    if req.method == 'POST':
        if req.META['REMOTE_ADDR'] == '127.0.0.1':
            username, password, topic, acc, clientid = unpack_POST_data(req)
            # need to handle
            #   django users
            #   django superusers
            #   websockets users
            #   LAMPI devices - broker bridges

            read_list, write_list = [], []

            user = None

            # try Django user
            try:
                user = User.objects.get(username=username)
                # if Django superuser, grant access to anything
                if user.is_superuser:
                    return HttpResponse(None, content_type='application/json')
            except User.DoesNotExist:
                pass

            if user is None:
                # try websockets_user
                try:
                    device = models.Lampi.objects.get(device_id=username)
                    user = device.user
                except models.Lampi.DoesNotExist:
                    pass

            if user is not None:
                read_list, write_list = get_acls_for_user(user)
            else:
                # try device_broker
                if username == clientid and clientid.endswith('_broker'):
                    device_id = clientid.split('_')[0]
                    read_list, write_list = get_acls_for_bridge(device_id)

            if acc in (ACL_READ, ACL_SUBSCRIBE) and read_list:
                for t in read_list:
                    print("ACL_READ: '{}' '{}'".format(t, topic))
                    if topic_matches_sub(t, topic):
                        print("  MATCH ACL_READ: '{}' '{}'".format(t, topic))
                        return HttpResponse(None,
                                            content_type='application/json')
            elif acc == ACL_WRITE and write_list:
                for t in write_list:
                    print("ACL_WRITE: '{}' '{}'".format(t, topic))
                    if topic_matches_sub(t, topic):
                        print("  MATCH ACL_WRITE: '{}' '{}'".format(t, topic))
                        return HttpResponse(None,
                                            content_type='application/json')
    return HttpResponseForbidden(None, content_type='application/json')
