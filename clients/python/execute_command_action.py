


from typing import Any

class ExecuteCommandAction(Action):
    def run(self, args: dict[str, Any]) -> str:
        # Craft the request and log the command
        request = {
            'action': 'execute_command',
            'args': {
                'cmd': args['cmd']
            }
        }
        HistoryService().add_command(args['cmd'])

        # Send the request and return the response
        response = HTTPService().send_request(request)
        return response['output']
