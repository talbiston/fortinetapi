import json
from collections import OrderedDict
import requests
from getpass import getpass



def sort_request(request):
    """
    Sort a JSON-RPC request dict.

    This has no effect other than making the request nicer to read.

        >>> json.dumps(sort_request(
        ...     {'id': 2, 'params': [2, 3], 'method': 'add', 'jsonrpc': '2.0'}))
        '{"jsonrpc": "2.0", "method": "add", "params": [2, 3], "id": 2}'

    Args:
        request: JSON-RPC request in dict format.
    """
    sort_order = ["jsonrpc", "method", "params", "id", "session"]
    return OrderedDict(sorted(request.items(), key=lambda k: sort_order.index(k[0])))


def fix_keys(kwargs):
        # get keys to change
        change_keys = []
        if kwargs:
            for k in kwargs.keys():
                if '_' in k:
                    change_keys.append(k)

        #change keys
        for i in change_keys:
            left, right = i.split('_')
            kwargs[f'{left}-{right}'] = kwargs.pop(i)
        return kwargs


class JsonRpc(dict):  # type: ignore

    def __init__(self, method: str, *args, **kwargs):
        super().__init__(jsonrpc="2.0", method=method)
        # Add the params to self.

        kwargs = fix_keys(kwargs)

        base_list = []
        if args and kwargs:
            # The 'params' can be *EITHER* "by-position" (a list) or "by-name" (a dict).
            # Therefore, in this case it violates the JSON-RPC 2.0 specification.
            # However, it provides the same behavior as the previous version of
            # jsonrpcclient to keep compatibility.
            # TODO: consider to raise a warning.

            print("Args: ",args)
            print("Kwargs:", kwargs)

            params_list = list(args)
            params_list.append(kwargs)
            self.update(params=params_list)
        elif args:
            self.update(params=list(args))
        elif kwargs:
            base_list.append(kwargs)
            self.update(params=base_list)

    def __json__(self):

        return sort_request(self)


class HTTPclient:

    def __init__(self, baseUrl):
        self.baseUrl = baseUrl


    def send(self, json):

        response = requests.post(self.baseUrl, json=json, verify=False)
        return response
