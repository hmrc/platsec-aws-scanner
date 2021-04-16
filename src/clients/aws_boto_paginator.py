from typing import Any, List, Optional, Tuple


class AwsBotoPaginator:
    def __init__(self, boto_action, boto_args, boto_max_results):  # type: ignore
        self._action = boto_action
        self._args = boto_args
        self._args.update({"MaxResults": boto_max_results})

    def paginate(self, response_key, response_mapper) -> List[Any]:  # type: ignore
        next_token, items = self._call_action(response_key, response_mapper)
        while next_token:
            next_token, next_items = self._call_action(response_key, response_mapper, next_token)
            items.extend(next_items)
        return items

    def _call_action(self, resp_key, resp_mapper, next_token=None) -> Tuple[Optional[str], List[Any]]:  # type: ignore
        response = self._action(NextToken=next_token, **self._args) if next_token else self._action(**self._args)
        return response["NextToken"] if "NextToken" in response else None, list(map(resp_mapper, response[resp_key]))
